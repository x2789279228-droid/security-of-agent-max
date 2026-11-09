import { useEffect, useState } from 'react'
import { getNavExpert, NAV_EXPERT_EVENT, setNavExpert } from '../lib/navPrefs'

/** 简约/专家模式开关（localStorage + 自定义事件同步） */
export function useNavExpert() {
  const [expert, setExpertState] = useState<boolean>(() => getNavExpert())

  useEffect(() => {
    const sync = () => setExpertState(getNavExpert())
    const onCustom = (e: Event) => {
      const detail = (e as CustomEvent<boolean>).detail
      setExpertState(typeof detail === 'boolean' ? detail : getNavExpert())
    }
    window.addEventListener('storage', sync)
    window.addEventListener(NAV_EXPERT_EVENT, onCustom)
    return () => {
      window.removeEventListener('storage', sync)
      window.removeEventListener(NAV_EXPERT_EVENT, onCustom)
    }
  }, [])

  return { expert, setExpert: setNavExpert }
}
