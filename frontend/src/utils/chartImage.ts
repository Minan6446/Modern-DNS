// Off-screen ECharts → PNG helper.
//
// Used by the monitoring report export pipeline (PDF + Excel) so we can
// embed the *same* charts the user sees on screen into the export
// artifacts. Rendering off-screen (rather than reading the on-page
// ECharts instances) keeps the export independent of the page's
// current viewport size and theme overrides — the PNG always comes out
// at the requested resolution.
//
// Implementation notes:
//   - Container is mounted to document.body and positioned far
//     off-screen with `pointer-events:none` so it never flashes.
//   - We force background to white because the report page sometimes
//     has a translucent card background, and a transparent PNG inside
//     a PDF page or Excel cell renders the unwanted card colour.
//   - Animations are disabled in the option overlay so getDataURL()
//     captures the final frame on the very first tick instead of a
//     half-drawn state.

import { echarts } from './echarts'

export interface RenderChartOptions {
  width?: number
  height?: number
  pixelRatio?: number
}

const DEFAULTS: Required<RenderChartOptions> = {
  width: 960,
  height: 540,
  pixelRatio: 2,
}

/**
 * Renders an ECharts option object to a base64 PNG data URL.
 * Returns an empty string when the option is unusable (e.g. no series
 * data) so the caller can skip the slot gracefully instead of
 * embedding a blank image.
 */
export async function renderEchartsOptionToPng(
  option: Record<string, any>,
  opts: RenderChartOptions = {},
): Promise<string> {
  const { width, height, pixelRatio } = { ...DEFAULTS, ...opts }
  if (!option || typeof option !== 'object') {
    return ''
  }

  const host = document.createElement('div')
  host.style.cssText = [
    'position:fixed',
    'left:-10000px',
    'top:-10000px',
    `width:${width}px`,
    `height:${height}px`,
    'pointer-events:none',
    'background:#ffffff',
  ].join(';')
  document.body.appendChild(host)

  const instance = echarts.init(host, undefined, {
    renderer: 'canvas',
    width,
    height,
    devicePixelRatio: pixelRatio,
  })

  try {
    instance.setOption(
      {
        ...option,
        animation: false,
        backgroundColor: '#ffffff',
      },
      true,
    )
    // Force a synchronous render before grabbing the URL. setOption
    // schedules an async render via rAF in some ECharts paths; calling
    // a layout-touching API like getWidth() drains it.
    instance.getWidth()
    return instance.getDataURL({
      type: 'png',
      pixelRatio,
      backgroundColor: '#ffffff',
    })
  } finally {
    instance.dispose()
    host.remove()
  }
}

/**
 * Strips the "data:image/png;base64," prefix so callers can hand the
 * raw bytes to libraries that expect a buffer (e.g. ExcelJS addImage
 * with `base64`). Returns empty string if input is falsy.
 */
export function dataUrlToBase64(dataUrl: string): string {
  if (!dataUrl) return ''
  const idx = dataUrl.indexOf(',')
  return idx >= 0 ? dataUrl.slice(idx + 1) : dataUrl
}

export interface RenderTextOptions {
  font?: string
  color?: string
  weight?: 'normal' | 'bold' | number
  /** Logical pixel size (CSS px). The output PNG is rendered at 2x. */
  fontSizePx?: number
  /** Padding around the text in CSS px. */
  paddingPx?: number
  /** Background colour. Defaults to transparent. */
  background?: string
}

/**
 * Rasterises a single line of text to a PNG data URL using a
 * standalone canvas. The default font stack is the same one
 * Element Plus uses and resolves to a CJK-capable system face on
 * Windows / macOS / Linux, so embedding the resulting PNG in a PDF
 * sidesteps jsPDF's lack of bundled CJK glyphs entirely.
 *
 * Returns:
 *   - dataUrl: base64 PNG ready for pdf.addImage / ExcelJS
 *   - widthPt / heightPt: physical PDF-pt dimensions matching the
 *     CSS-pixel layout the caller asked for (1 CSS px == 1 pt at
 *     the default jsPDF unit setting).
 */
export function renderTextToPng(
  text: string,
  opts: RenderTextOptions = {},
): { dataUrl: string; widthPt: number; heightPt: number } {
  const {
    font = '-apple-system, "Segoe UI", "PingFang SC", "Microsoft YaHei", "Helvetica Neue", Arial, sans-serif',
    color = '#1d2129',
    weight = 'normal',
    fontSizePx = 14,
    paddingPx = 2,
    background,
  } = opts
  const scale = 2
  const fontString = `${weight === 'bold' ? 'bold ' : typeof weight === 'number' ? `${weight} ` : ''}${fontSizePx * scale}px ${font}`

  const measure = document.createElement('canvas').getContext('2d')!
  measure.font = fontString
  const metrics = measure.measureText(text || '')
  const widthDev = Math.ceil(metrics.width) + paddingPx * 2 * scale
  const heightDev = Math.ceil(fontSizePx * scale * 1.4) + paddingPx * 2 * scale

  const canvas = document.createElement('canvas')
  canvas.width = widthDev
  canvas.height = heightDev
  const ctx = canvas.getContext('2d')!
  if (background) {
    ctx.fillStyle = background
    ctx.fillRect(0, 0, widthDev, heightDev)
  }
  ctx.font = fontString
  ctx.textBaseline = 'middle'
  ctx.fillStyle = color
  ctx.fillText(text || '', paddingPx * scale, heightDev / 2)

  return {
    dataUrl: canvas.toDataURL('image/png'),
    widthPt: widthDev / scale,
    heightPt: heightDev / scale,
  }
}
