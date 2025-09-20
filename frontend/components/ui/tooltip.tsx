"use client";

import { useEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'

/**
 * Tooltip（点击触发 + Portal）
 * - 使用 portal 渲染到 body，避免被父容器 overflow 裁剪
 * - 点击问号切换显示，再次点击或点击外部关闭
 */
export function Tooltip({ text }: { text: string }) {
  const [open, setOpen] = useState(false)
  const [pos, setPos] = useState<{top:number;left:number;width:number}>({top:0,left:0,width:0})
  const ref = useRef<HTMLSpanElement>(null)

  const toggle = () => {
    const el = ref.current
    if (!el) return
    const r = el.getBoundingClientRect()
    setPos({ top: r.bottom + 8, left: r.left, width: r.width })
    setOpen(o=>!o)
  }

  useEffect(() => {
    if (!open) return
    const onClick = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    const onScroll = () => setOpen(false)
    window.addEventListener('mousedown', onClick)
    window.addEventListener('scroll', onScroll, true)
    window.addEventListener('resize', onScroll)
    return () => {
      window.removeEventListener('mousedown', onClick)
      window.removeEventListener('scroll', onScroll, true)
      window.removeEventListener('resize', onScroll)
    }
  }, [open])

  return (
    <span ref={ref} className="inline-flex items-center ml-2 align-middle select-none">
      <button type="button" onClick={toggle} aria-label="帮助"
        className="inline-flex items-center justify-center h-4 w-4 rounded-full text-[10px] font-bold bg-input/60 text-muted-foreground border border-border cursor-pointer hover:bg-input/80">
        ?
      </button>
      {open && createPortal(
        <div style={{ position:'fixed', top: pos.top, left: Math.max(8, pos.left-4), zIndex: 9999 }}>
          <div className="max-w-xs text-xs bg-foreground text-background px-2 py-1 rounded border border-border shadow">
            {text}
          </div>
        </div>,
        document.body
      )}
    </span>
  )
}
