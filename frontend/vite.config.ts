import { defineConfig, loadEnv } from 'vite'
import vue from '@vitejs/plugin-vue'
import Components from 'unplugin-vue-components/vite'
import ElementPlus from 'unplugin-element-plus/vite'
import { ElementPlusResolver } from 'unplugin-vue-components/resolvers'

const ELEMENT_PLUS_CHUNK_PACKAGES = ['node_modules/element-plus/']
const ECHARTS_CHUNK_PACKAGES = [
  'node_modules/echarts/',
  'node_modules/zrender/',
  'node_modules/vue-echarts/',
]
const CORE_CHUNK_PACKAGES = ['node_modules/vue-router/', 'node_modules/pinia/']
const COMPOSABLES_PATH = '/src/composables/'

// https://vite.dev/config/
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  const apiBase = env.VITE_API_BASE_URL || 'http://10.0.11.24:8080'
  const isDev = mode === 'development'

  return {
    resolve: {
      alias: {
        '@': new URL('./src', import.meta.url).pathname,
      },
    },
    plugins: [
      vue(),
      Components({
        resolvers: [
          ElementPlusResolver({
            importStyle: 'sass',
          }),
        ],
      }),
      ElementPlus({
        useSource: true,
      }),
    ],
    server: isDev
      ? {
          proxy: {
            '/api': {
              target: apiBase,
              changeOrigin: true,
              secure: false,
            },
          },
        }
      : undefined,
    esbuild: {
      drop: ['console', 'debugger'],
    },
    build: {
      target: 'es2020',
      cssCodeSplit: true,
      reportCompressedSize: false,
      rollupOptions: {
        output: {
          manualChunks(id) {
            if (ELEMENT_PLUS_CHUNK_PACKAGES.some((pkg) => id.includes(pkg))) {
              return 'v-element'
            }
            if (ECHARTS_CHUNK_PACKAGES.some((pkg) => id.includes(pkg))) {
              return 'v-charts'
            }
            if (CORE_CHUNK_PACKAGES.some((pkg) => id.includes(pkg))) {
              return 'v-core'
            }
            if (id.includes(COMPOSABLES_PATH)) {
              return 'v-composables'
            }
          },
        },
      },
    },
  }
})
