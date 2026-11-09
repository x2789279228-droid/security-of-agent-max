import { NAV_GROUPS, isAdvancedNavItem, type NavGroup, type NavItem } from '../layouts/nav'

/**
 * 导航偏好：简洁模式（默认）/ 专家模式。
 *
 * 目的：默认只显示值班主线（7 项），高级能力收进专家模式；
 * 不删除任何页面，命令面板（Ctrl K）与 URL 始终可达。
 * 存储用 localStorage，跨路由/刷新保留；切换时广播事件让 TopNav 与 Home 同步。
 */

export const NAV_EXPERT_KEY = 'soc_nav_expert'
export const NAV_EXPERT_EVENT = 'soc:nav-expert-change'

export function getNavExpert(): boolean {
  try {
    return localStorage.getItem(NAV_EXPERT_KEY) === '1'
  } catch {
    return false
  }
}

export function setNavExpert(next: boolean) {
  try {
    localStorage.setItem(NAV_EXPERT_KEY, next ? '1' : '0')
  } catch {
    /* 隐私模式：仅当前会话生效（由事件驱动，不落盘也能切换） */
  }
  window.dispatchEvent(new CustomEvent(NAV_EXPERT_EVENT, { detail: next }))
}

/** 简洁模式过滤：只留 core；当前所在页即使属于高级能力也保留，避免"看不到自己在哪" */
export function visibleNavGroups(expert: boolean, currentPath?: string): NavGroup[] {
  return NAV_GROUPS.map((group) => ({
    ...group,
    items: group.items.filter((item) => expert || !isAdvancedNavItem(item) || item.path === currentPath),
  }))
}

/** 简洁模式下被隐藏的条目总数 */
export function hiddenAdvancedCount(): number {
  return NAV_GROUPS.reduce(
    (n, g) => n + g.items.filter((i) => isAdvancedNavItem(i)).length,
    0,
  )
}

/** 某个分组在简洁模式下隐藏的条目数（保留当前页时不计入） */
export function hiddenAdvancedCountInGroup(group: NavGroup, currentPath?: string): number {
  return group.items.filter(
    (i) => isAdvancedNavItem(i) && i.path !== currentPath,
  ).length
}

export function flattenNavItems(groups: NavGroup[]): (NavItem & { group: string })[] {
  return groups.flatMap((g) => g.items.map((item) => ({ ...item, group: g.title })))
}
