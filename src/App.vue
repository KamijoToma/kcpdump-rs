<script setup lang="ts">
import { ref, computed, h } from "vue";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import {
  NButton,
  NCard,
  NPagination,
  NInput,
  NSpace,
  NDivider,
  NEmpty,
  NLayout,
  NLayoutHeader,
  NLayoutContent,
  NMessageProvider,
  NTag,
  createDiscreteApi,
  NDataTable,
} from "naive-ui";

const filePath = ref("");
const packets = ref<{ ethType: string; source: string; target: string }[]>([]);
const isLoading = ref(false);

const currentPage = ref(1);
const packetsPerPage = ref(5);

// 创建离散API用于全局消息
const { message } = createDiscreteApi(['message']);

const paginatedPackets = computed(() => {
  const start = (currentPage.value - 1) * packetsPerPage.value;
  const end = start + packetsPerPage.value;
  return packets.value.slice(start, end);
});

const totalPages = computed(() => {
  return Math.ceil(packets.value.length / packetsPerPage.value);
});

function handlePageChange(page: number) {
  currentPage.value = page;
}

function handlePageSizeChange(pageSize: number) {
  packetsPerPage.value = pageSize;
  currentPage.value = 1;
}

async function pickFile() {
  const selected = await open({
    filters: [{ name: "PCAP Files", extensions: ["pcap"] }],
  });
  if (selected && typeof selected === "string") {
    filePath.value = selected;
    await analyzeFile();
  }
}

async function analyzeFile() {
  if (!filePath.value) return;
  try {
    isLoading.value = true;
    packets.value = await invoke("analyze_pcap", { filePath: filePath.value });
    console.log("Packets:", packets.value);
    
    if (packets.value.length) {
      message.success(`成功加载 ${packets.value.length} 个数据包`);
    } else {
      message.warning("未找到数据包或无法解析文件");
    }
  } catch (error) {
    message.error(`分析文件失败: ${error}`);
    console.error(error);
  } finally {
    isLoading.value = false;
  }
}

// 创建表格列
const columns = [
  {
    title: "类型",
    key: "ethType",
    render: (row: { ethType: string }) => {
      return h(NTag, { type: "info", bordered: false }, { default: () => row.ethType });
    }
  },
  {
    title: "源地址",
    key: "source",
  },
  {
    title: "目标地址",
    key: "target",
  },
];
</script>

<template>
  <NMessageProvider>
    <NLayout position="absolute" class="bg-gray-50">
      <NLayoutHeader bordered class="p-4 bg-white shadow-sm">
        <div class="text-2xl font-bold text-center text-green-600">PCAP 文件分析器</div>
      </NLayoutHeader>
      <NLayoutContent class="p-6">
        <NCard class="max-w-4xl mx-auto">
          <NSpace vertical size="large" class="w-full">
            <div class="flex items-center space-x-4">
              <NButton type="primary" @click="pickFile" :loading="isLoading">
                选择 PCAP 文件
              </NButton>
              <NInput
                v-if="filePath"
                v-model:value="filePath"
                readonly
                placeholder="未选择文件"
                class="flex-grow"
              />
            </div>
            
            <NDivider v-if="packets.length" />
            
            <div v-if="isLoading" class="text-center py-8">
              <div class="text-lg text-gray-600">加载中...</div>
            </div>
            
            <div v-else-if="packets.length">
              <NDataTable
                :columns="columns"
                :data="paginatedPackets"
                :bordered="false"
                :single-line="false"
                class="mb-4"
              />
              
              <div class="flex justify-between items-center mt-4">
                <div class="text-sm text-gray-500">
                  共 {{ packets.length }} 个数据包
                </div>
                <NPagination
                  v-model:page="currentPage"
                  v-model:page-size="packetsPerPage"
                  :page-count="totalPages"
                  :page-sizes="[5, 10, 20, 50, 100]"
                  show-size-picker
                  @update:page="handlePageChange"
                  @update:page-size="handlePageSizeChange"
                />
              </div>
            </div>
            
            <NEmpty 
              v-else-if="filePath"
              description="未找到数据包或无法解析文件"
              class="py-8"
            />
          </NSpace>
        </NCard>
      </NLayoutContent>
    </NLayout>
  </NMessageProvider>
</template>

<style>
/* 导入 Tailwind */
@import "tailwindcss";
</style>