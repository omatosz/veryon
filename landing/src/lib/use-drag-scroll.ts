import { useEffect, useRef, useState } from 'react'

export function useDragScroll<T extends HTMLElement>() {
  const ref = useRef<T>(null)
  const [dragging, setDragging] = useState(false)

  useEffect(() => {
    const el = ref.current
    if (!el) return

    let isDown = false
    let startX = 0
    let startScroll = 0

    function onDown(e: MouseEvent) {
      isDown = true
      startX = e.pageX
      startScroll = el!.scrollLeft
    }

    function onMove(e: MouseEvent) {
      if (!isDown) return
      const walk = e.pageX - startX
      if (Math.abs(walk) > 4) setDragging(true)
      el!.scrollLeft = startScroll - walk
    }

    function onUp() {
      if (!isDown) return
      isDown = false
      setTimeout(() => setDragging(false), 0)
    }

    el.addEventListener('mousedown', onDown)
    window.addEventListener('mousemove', onMove)
    window.addEventListener('mouseup', onUp)
    return () => {
      el.removeEventListener('mousedown', onDown)
      window.removeEventListener('mousemove', onMove)
      window.removeEventListener('mouseup', onUp)
    }
  }, [])

  return { ref, dragging }
}
