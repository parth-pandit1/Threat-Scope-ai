"""
MinIO object storage client wrapper.

Provides synchronous helpers for bucket management, file upload,
and file download. Used by both the FastAPI upload endpoint and
RQ worker tasks (MinIO's Python SDK is synchronous).
"""

import io
import logging

from minio import Minio
from minio.error import S3Error

from app.core.config import settings

logger = logging.getLogger(__name__)


def get_minio_client() -> Minio:
    """Create and return a configured MinIO client instance."""
    return Minio(
        endpoint=settings.MINIO_ENDPOINT,
        access_key=settings.MINIO_ACCESS_KEY,
        secret_key=settings.MINIO_SECRET_KEY,
        secure=settings.MINIO_SECURE,
        region=settings.MINIO_REGION,
    )


def ensure_bucket_exists(client: Minio, bucket_name: str) -> None:
    """
    Create the specified bucket if it does not already exist.

    Args:
        client: An initialised MinIO client.
        bucket_name: Name of the bucket to verify / create.

    Raises:
        S3Error: If the MinIO API call fails.
    """
    try:
        if not client.bucket_exists(bucket_name):
            client.make_bucket(bucket_name)
            logger.info("Created MinIO bucket: %s", bucket_name)
        else:
            logger.debug("MinIO bucket already exists: %s", bucket_name)
    except S3Error as exc:
        logger.error("Failed to ensure bucket '%s' exists: %s", bucket_name, str(exc))
        raise


def upload_file(
    file_data: bytes,
    object_name: str,
    content_type: str = "application/octet-stream",
) -> str:
    """
    Upload raw bytes to MinIO as a named object.

    Args:
        file_data: File content as bytes.
        object_name: Full key/path within the bucket.
        content_type: MIME type of the file.

    Returns:
        The ``object_name`` on success.

    Raises:
        S3Error: If the upload fails.
    """
    client = get_minio_client()
    ensure_bucket_exists(client, settings.MINIO_BUCKET)

    try:
        client.put_object(
            bucket_name=settings.MINIO_BUCKET,
            object_name=object_name,
            data=io.BytesIO(file_data),
            length=len(file_data),
            content_type=content_type,
        )
        logger.info(
            "Uploaded object to MinIO: %s/%s (%d bytes)",
            settings.MINIO_BUCKET,
            object_name,
            len(file_data),
        )
        return object_name
    except S3Error as exc:
        logger.error("MinIO upload failed for '%s': %s", object_name, str(exc))
        raise


def download_file(object_name: str) -> bytes:
    """
    Download an object from MinIO and return its content as bytes.

    Args:
        object_name: Full key/path within the bucket.

    Returns:
        Raw file bytes.

    Raises:
        S3Error: If the download fails.
    """
    client = get_minio_client()
    try:
        response = client.get_object(settings.MINIO_BUCKET, object_name)
        data = response.read()
        response.close()
        response.release_conn()
        logger.info(
            "Downloaded object from MinIO: %s/%s (%d bytes)",
            settings.MINIO_BUCKET,
            object_name,
            len(data),
        )
        return data
    except S3Error as exc:
        logger.error("MinIO download failed for '%s': %s", object_name, str(exc))
        raise


def get_presigned_url(object_name: str, expires_hours: int = 24) -> str:
    """
    Generate a presigned GET URL for a MinIO object.
    
    Replaces the internal container address with the public external address
    so that client browsers can fetch the image.
    """
    from datetime import timedelta
    client = get_minio_client()
    try:
        url = client.presigned_get_object(
            bucket_name=settings.MINIO_BUCKET,
            object_name=object_name,
            expires=timedelta(hours=expires_hours),
        )
        # If running inside docker, replace internal endpoint with public endpoint
        if "minio:9000" in url:
            url = url.replace("http://minio:9000", settings.MINIO_PUBLIC_URL).replace("https://minio:9000", settings.MINIO_PUBLIC_URL)
        return url
    except Exception as exc:
        logger.error("Failed to generate presigned URL for '%s': %s", object_name, str(exc))
        # Fallback to direct public url structure
        return f"{settings.MINIO_PUBLIC_URL}/{settings.MINIO_BUCKET}/{object_name}"
