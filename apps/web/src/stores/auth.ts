import { defineStore } from "pinia";
import { request, ApiError } from "@/lib/api";
import { startSessionKeepalive, stopSessionKeepalive } from "@/lib/session";

type User = { id: string; displayName: string };

export const useAuthStore = defineStore("auth", {
  state: () => ({
    initialized: false,
    loaded: false,
    user: null as User | null
  }),
  actions: {
    setUser(user: User | null) {
      this.user = user;
      if (user) startSessionKeepalive();
      else stopSessionKeepalive();
    },
    async bootstrap() {
      if (this.loaded) return;
      const status = await request<{ data: { initialized: boolean } }>("/setup/status");
      this.initialized = status.data.initialized;
      if (this.initialized) {
        try {
          const session = await request<{ data: User }>("/auth/me");
          this.setUser(session.data);
        } catch (error) {
          if (!(error instanceof ApiError) || error.status !== 401) throw error;
          this.user = null;
        }
      }
      this.loaded = true;
    },
    async setup(displayName: string, password: string) {
      const result = await request<{ data: User }>("/setup", { method: "POST", body: { displayName, password } });
      this.initialized = true;
      this.setUser(result.data);
    },
    async login(password: string) {
      const result = await request<{ data: User }>("/auth/login", { method: "POST", body: { password } });
      this.setUser(result.data);
    },
    async logout() {
      try {
        await request<void>("/auth/logout", { method: "POST" });
      } finally {
        this.setUser(null);
      }
    }
  }
});
