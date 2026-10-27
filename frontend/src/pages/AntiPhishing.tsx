import { useState } from 'react'
import { PageFrame, tabOn, tabOff } from '../components/common/PageFrame'
import { PageTransition } from '../components/common/PageTransition'
import PhishingDetect from '../components/phishing/PhishingDetect'
import PhishingDrill from '../components/phishing/PhishingDrill'

/**
 * 反钓鱼(阶段 5) — 接线此前的孤儿组件 PhishingDetect/PhishingDrill:
 * 6+1 通道检测(email/web/domain/attachment/sms/qrcode/bec)+ 演练,
 * 后端 /api/phishing/* 端点早已齐备,此处补齐 UI 入口。
 */
export default function AntiPhishing() {
  const [tab, setTab] = useState<'detect' | 'drill'>('detect')

  return (
    <PageTransition>
      <PageFrame
        num="Ⅵ"
        title="反钓鱼"
        hint="六通道检测 · BEC 识别 · 演练闭环。"
        marginalia="——钓的是人,防的也是人。"
        extra={
          <div className="flex items-center gap-4">
            <button onClick={() => setTab('detect')} className={tab === 'detect' ? tabOn : tabOff}>
              检测
            </button>
            <button onClick={() => setTab('drill')} className={tab === 'drill' ? tabOn : tabOff}>
              演练
            </button>
          </div>
        }
      >
        {tab === 'detect' ? <PhishingDetect /> : <PhishingDrill />}
      </PageFrame>
    </PageTransition>
  )
}
