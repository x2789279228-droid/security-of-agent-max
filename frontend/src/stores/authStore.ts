import { create } from 'zustand'

interface AuthState {
  token: string | null
  username: string | null
  /** 开放体验模式(2026-11-10): 后端 auth_open_tour=true 时为 true ——
   *  fetchJSON/TopNav/Login 据此跳过登出与 401 跳登录行为 */
  openTour: boolean
  setOpenTour: (v: boolean) => void
  setAuth: (token: string, username: string) => void
  logout: () => void
  isAuthenticated: () => boolean
}

export const useAuthStore = create<AuthState>((set, get) => ({
  token: localStorage.getItem('sm_token'),
  username: localStorage.getItem('sm_user'),
  openTour: localStorage.getItem('sm_open_tour') === '1',
  setOpenTour: (v) => {
    localStorage.setItem('sm_open_tour', v ? '1' : '0')
    set({ openTour: v })
  },

  setAuth: (token, username) => {
    localStorage.setItem('sm_token', token)
    localStorage.setItem('sm_user', username)
    set({ token, username })
  },

  logout: () => {
    localStorage.removeItem('sm_token')
    localStorage.removeItem('sm_user')
    set({ token: null, username: null })
  },

  isAuthenticated: () => !!get().token,
}))
