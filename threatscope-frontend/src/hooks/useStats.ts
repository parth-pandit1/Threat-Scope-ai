import { useState, useEffect } from "react";
import { api } from "@/lib/api";
import type { PlatformStats } from "@/types";

let cachedStats: PlatformStats | null = null;
let lastFetchTime: number = 0;
const CACHE_DURATION = 60 * 1000; // 60 seconds

export function useStats() {
  const [stats, setStats] = useState<PlatformStats | null>(cachedStats);
  const [loading, setLoading] = useState<boolean>(!cachedStats);

  useEffect(() => {
    const fetchStats = async () => {
      const now = Date.now();
      if (cachedStats && now - lastFetchTime < CACHE_DURATION) {
        setStats(cachedStats);
        setLoading(false);
        return;
      }

      try {
        setLoading(true);
        const data = await api.stats();
        cachedStats = data;
        lastFetchTime = Date.now();
        setStats(data);
      } catch (error) {
        console.error("Failed to fetch stats:", error);
      } finally {
        setLoading(false);
      }
    };

    fetchStats();
  }, []);

  return { stats, loading };
}
