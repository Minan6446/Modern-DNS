// vite.config.ts
import { defineConfig } from "file:///C:/Users/minan/Desktop/Modern-DNS/node_modules/vite/dist/node/index.js";
import vue from "file:///C:/Users/minan/Desktop/Modern-DNS/node_modules/@vitejs/plugin-vue/dist/index.mjs";
import Components from "file:///C:/Users/minan/Desktop/Modern-DNS/node_modules/unplugin-vue-components/dist/vite.mjs";
import ElementPlus from "file:///C:/Users/minan/Desktop/Modern-DNS/node_modules/unplugin-element-plus/dist/vite.mjs";
import { ElementPlusResolver } from "file:///C:/Users/minan/Desktop/Modern-DNS/node_modules/unplugin-vue-components/dist/resolvers.mjs";
var __vite_injected_original_import_meta_url = "file:///C:/Users/minan/Desktop/Modern-DNS/vite.config.ts";
var ELEMENT_PLUS_CHUNK_PACKAGES = ["node_modules/element-plus/"];
var ECHARTS_CHUNK_PACKAGES = [
  "node_modules/echarts/",
  "node_modules/zrender/",
  "node_modules/vue-echarts/"
];
var CORE_CHUNK_PACKAGES = ["node_modules/vue-router/", "node_modules/pinia/"];
var COMPOSABLES_PATH = "/src/composables/";
var vite_config_default = defineConfig({
  resolve: {
    alias: {
      "@": new URL("./src", __vite_injected_original_import_meta_url).pathname
    }
  },
  plugins: [
    vue(),
    Components({
      resolvers: [
        ElementPlusResolver({
          importStyle: "sass"
        })
      ]
    }),
    ElementPlus({
      useSource: true
    })
  ],
  esbuild: {
    drop: ["console", "debugger"]
  },
  build: {
    target: "es2020",
    cssCodeSplit: true,
    reportCompressedSize: false,
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (ELEMENT_PLUS_CHUNK_PACKAGES.some((pkg) => id.includes(pkg))) {
            return "v-element";
          }
          if (ECHARTS_CHUNK_PACKAGES.some((pkg) => id.includes(pkg))) {
            return "v-charts";
          }
          if (CORE_CHUNK_PACKAGES.some((pkg) => id.includes(pkg))) {
            return "v-core";
          }
          if (id.includes(COMPOSABLES_PATH)) {
            return "v-composables";
          }
        }
      }
    }
  }
});
export {
  vite_config_default as default
};
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsidml0ZS5jb25maWcudHMiXSwKICAic291cmNlc0NvbnRlbnQiOiBbImNvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9kaXJuYW1lID0gXCJDOlxcXFxVc2Vyc1xcXFxtaW5hblxcXFxEZXNrdG9wXFxcXE1vZGVybi1ETlNcIjtjb25zdCBfX3ZpdGVfaW5qZWN0ZWRfb3JpZ2luYWxfZmlsZW5hbWUgPSBcIkM6XFxcXFVzZXJzXFxcXG1pbmFuXFxcXERlc2t0b3BcXFxcTW9kZXJuLUROU1xcXFx2aXRlLmNvbmZpZy50c1wiO2NvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9pbXBvcnRfbWV0YV91cmwgPSBcImZpbGU6Ly8vQzovVXNlcnMvbWluYW4vRGVza3RvcC9Nb2Rlcm4tRE5TL3ZpdGUuY29uZmlnLnRzXCI7aW1wb3J0IHsgZGVmaW5lQ29uZmlnIH0gZnJvbSAndml0ZSdcbmltcG9ydCB2dWUgZnJvbSAnQHZpdGVqcy9wbHVnaW4tdnVlJ1xuaW1wb3J0IENvbXBvbmVudHMgZnJvbSAndW5wbHVnaW4tdnVlLWNvbXBvbmVudHMvdml0ZSdcbmltcG9ydCBFbGVtZW50UGx1cyBmcm9tICd1bnBsdWdpbi1lbGVtZW50LXBsdXMvdml0ZSdcbmltcG9ydCB7IEVsZW1lbnRQbHVzUmVzb2x2ZXIgfSBmcm9tICd1bnBsdWdpbi12dWUtY29tcG9uZW50cy9yZXNvbHZlcnMnXG5cbmNvbnN0IEVMRU1FTlRfUExVU19DSFVOS19QQUNLQUdFUyA9IFsnbm9kZV9tb2R1bGVzL2VsZW1lbnQtcGx1cy8nXVxuY29uc3QgRUNIQVJUU19DSFVOS19QQUNLQUdFUyA9IFtcbiAgJ25vZGVfbW9kdWxlcy9lY2hhcnRzLycsXG4gICdub2RlX21vZHVsZXMvenJlbmRlci8nLFxuICAnbm9kZV9tb2R1bGVzL3Z1ZS1lY2hhcnRzLycsXG5dXG5jb25zdCBDT1JFX0NIVU5LX1BBQ0tBR0VTID0gWydub2RlX21vZHVsZXMvdnVlLXJvdXRlci8nLCAnbm9kZV9tb2R1bGVzL3BpbmlhLyddXG5jb25zdCBDT01QT1NBQkxFU19QQVRIID0gJy9zcmMvY29tcG9zYWJsZXMvJ1xuXG4vLyBodHRwczovL3ZpdGUuZGV2L2NvbmZpZy9cbmV4cG9ydCBkZWZhdWx0IGRlZmluZUNvbmZpZyh7XG4gIHJlc29sdmU6IHtcbiAgICBhbGlhczoge1xuICAgICAgJ0AnOiBuZXcgVVJMKCcuL3NyYycsIGltcG9ydC5tZXRhLnVybCkucGF0aG5hbWUsXG4gICAgfSxcbiAgfSxcbiAgcGx1Z2luczogW1xuICAgIHZ1ZSgpLFxuICAgIENvbXBvbmVudHMoe1xuICAgICAgcmVzb2x2ZXJzOiBbXG4gICAgICAgIEVsZW1lbnRQbHVzUmVzb2x2ZXIoe1xuICAgICAgICAgIGltcG9ydFN0eWxlOiAnc2FzcycsXG4gICAgICAgIH0pLFxuICAgICAgXSxcbiAgICB9KSxcbiAgICBFbGVtZW50UGx1cyh7XG4gICAgICB1c2VTb3VyY2U6IHRydWUsXG4gICAgfSksXG4gIF0sXG4gIGVzYnVpbGQ6IHtcbiAgICBkcm9wOiBbJ2NvbnNvbGUnLCAnZGVidWdnZXInXSxcbiAgfSxcbiAgYnVpbGQ6IHtcbiAgICB0YXJnZXQ6ICdlczIwMjAnLFxuICAgIGNzc0NvZGVTcGxpdDogdHJ1ZSxcbiAgICByZXBvcnRDb21wcmVzc2VkU2l6ZTogZmFsc2UsXG4gICAgcm9sbHVwT3B0aW9uczoge1xuICAgICAgb3V0cHV0OiB7XG4gICAgICAgIG1hbnVhbENodW5rcyhpZCkge1xuICAgICAgICAgIGlmIChFTEVNRU5UX1BMVVNfQ0hVTktfUEFDS0FHRVMuc29tZSgocGtnKSA9PiBpZC5pbmNsdWRlcyhwa2cpKSkge1xuICAgICAgICAgICAgcmV0dXJuICd2LWVsZW1lbnQnXG4gICAgICAgICAgfVxuICAgICAgICAgIGlmIChFQ0hBUlRTX0NIVU5LX1BBQ0tBR0VTLnNvbWUoKHBrZykgPT4gaWQuaW5jbHVkZXMocGtnKSkpIHtcbiAgICAgICAgICAgIHJldHVybiAndi1jaGFydHMnXG4gICAgICAgICAgfVxuICAgICAgICAgIGlmIChDT1JFX0NIVU5LX1BBQ0tBR0VTLnNvbWUoKHBrZykgPT4gaWQuaW5jbHVkZXMocGtnKSkpIHtcbiAgICAgICAgICAgIHJldHVybiAndi1jb3JlJ1xuICAgICAgICAgIH1cbiAgICAgICAgICBpZiAoaWQuaW5jbHVkZXMoQ09NUE9TQUJMRVNfUEFUSCkpIHtcbiAgICAgICAgICAgIHJldHVybiAndi1jb21wb3NhYmxlcydcbiAgICAgICAgICB9XG4gICAgICAgIH0sXG4gICAgICB9LFxuICAgIH0sXG4gIH0sXG59KVxuIl0sCiAgIm1hcHBpbmdzIjogIjtBQUErUixTQUFTLG9CQUFvQjtBQUM1VCxPQUFPLFNBQVM7QUFDaEIsT0FBTyxnQkFBZ0I7QUFDdkIsT0FBTyxpQkFBaUI7QUFDeEIsU0FBUywyQkFBMkI7QUFKK0ksSUFBTSwyQ0FBMkM7QUFNcE8sSUFBTSw4QkFBOEIsQ0FBQyw0QkFBNEI7QUFDakUsSUFBTSx5QkFBeUI7QUFBQSxFQUM3QjtBQUFBLEVBQ0E7QUFBQSxFQUNBO0FBQ0Y7QUFDQSxJQUFNLHNCQUFzQixDQUFDLDRCQUE0QixxQkFBcUI7QUFDOUUsSUFBTSxtQkFBbUI7QUFHekIsSUFBTyxzQkFBUSxhQUFhO0FBQUEsRUFDMUIsU0FBUztBQUFBLElBQ1AsT0FBTztBQUFBLE1BQ0wsS0FBSyxJQUFJLElBQUksU0FBUyx3Q0FBZSxFQUFFO0FBQUEsSUFDekM7QUFBQSxFQUNGO0FBQUEsRUFDQSxTQUFTO0FBQUEsSUFDUCxJQUFJO0FBQUEsSUFDSixXQUFXO0FBQUEsTUFDVCxXQUFXO0FBQUEsUUFDVCxvQkFBb0I7QUFBQSxVQUNsQixhQUFhO0FBQUEsUUFDZixDQUFDO0FBQUEsTUFDSDtBQUFBLElBQ0YsQ0FBQztBQUFBLElBQ0QsWUFBWTtBQUFBLE1BQ1YsV0FBVztBQUFBLElBQ2IsQ0FBQztBQUFBLEVBQ0g7QUFBQSxFQUNBLFNBQVM7QUFBQSxJQUNQLE1BQU0sQ0FBQyxXQUFXLFVBQVU7QUFBQSxFQUM5QjtBQUFBLEVBQ0EsT0FBTztBQUFBLElBQ0wsUUFBUTtBQUFBLElBQ1IsY0FBYztBQUFBLElBQ2Qsc0JBQXNCO0FBQUEsSUFDdEIsZUFBZTtBQUFBLE1BQ2IsUUFBUTtBQUFBLFFBQ04sYUFBYSxJQUFJO0FBQ2YsY0FBSSw0QkFBNEIsS0FBSyxDQUFDLFFBQVEsR0FBRyxTQUFTLEdBQUcsQ0FBQyxHQUFHO0FBQy9ELG1CQUFPO0FBQUEsVUFDVDtBQUNBLGNBQUksdUJBQXVCLEtBQUssQ0FBQyxRQUFRLEdBQUcsU0FBUyxHQUFHLENBQUMsR0FBRztBQUMxRCxtQkFBTztBQUFBLFVBQ1Q7QUFDQSxjQUFJLG9CQUFvQixLQUFLLENBQUMsUUFBUSxHQUFHLFNBQVMsR0FBRyxDQUFDLEdBQUc7QUFDdkQsbUJBQU87QUFBQSxVQUNUO0FBQ0EsY0FBSSxHQUFHLFNBQVMsZ0JBQWdCLEdBQUc7QUFDakMsbUJBQU87QUFBQSxVQUNUO0FBQUEsUUFDRjtBQUFBLE1BQ0Y7QUFBQSxJQUNGO0FBQUEsRUFDRjtBQUNGLENBQUM7IiwKICAibmFtZXMiOiBbXQp9Cg==
