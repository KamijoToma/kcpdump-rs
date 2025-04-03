<script setup lang="ts">
import { ref, computed } from "vue";
import { invoke } from "@tauri-apps/api/core";
import {
  NCard,
  NDivider,
  NEmpty,
  NLayout,
  NLayoutHeader,
  NLayoutContent,
  NMessageProvider,
  NSpace,
  NTabs,
  NTabPane,
  createDiscreteApi,
  NConfigProvider
} from "naive-ui";

// 导入子组件
import FileSelector from './components/FileSelector.vue';
import EthernetPacketsTable from './components/EthernetPacketsTable.vue';
import IPv4Filter from './components/IPv4Filter.vue';
import IPv4PacketsTable from './components/IPv4PacketsTable.vue';
import IPAddressCharts from './components/IPAddressCharts.vue';

const filePath = ref("");
const packets = ref<{
  ethType: string;
  source: string;
  target: string;
  tsSec: number;
  tsUsec: number;
}[]>([]);
const ipv4Packets = ref<{
  sourceIp: string;
  destIp: string;
  protocol: number;
  ttl: number;
  tsSec: number;
  tsUsec: number;
  totalLength: number;
}[]>([]);
const isLoading = ref(false);
const activeTab = ref("ethernet");

// 创建离散API用于全局消息
const { message } = createDiscreteApi(['message']);

// 筛选条件
const ipv4Filter = ref({
  startTime: null as number | null,
  endTime: null as number | null,
  ipAddress: "",
  direction: "any" // 'source', 'dest', 'any'
});

// 是否已应用筛选
const isFiltered = ref(false);

// 筛选后的IPv4数据包
const filteredIpv4Packets = computed(() => {
  if (!isFiltered.value) return ipv4Packets.value;

  return ipv4Packets.value.filter(packet => {
    // 时间过滤
    const packetTime = packet.tsSec * 1000 + Math.floor(packet.tsUsec / 1000);
    const timeMatches =
      (!ipv4Filter.value.startTime || packetTime >= ipv4Filter.value.startTime) &&
      (!ipv4Filter.value.endTime || packetTime <= ipv4Filter.value.endTime);

    if (!timeMatches) return false;

    // IP过滤
    if (ipv4Filter.value.ipAddress) {
      switch (ipv4Filter.value.direction) {
        case "source":
          return packet.sourceIp === ipv4Filter.value.ipAddress;
        case "dest":
          return packet.destIp === ipv4Filter.value.ipAddress;
        case "any":
          return packet.sourceIp === ipv4Filter.value.ipAddress ||
            packet.destIp === ipv4Filter.value.ipAddress;
        default:
          return true;
      }
    }

    return true;
  });
});

function applyFilter() {
  isFiltered.value = true;
  message.success("已应用筛选");
}

function clearFilter() {
  ipv4Filter.value = {
    startTime: null,
    endTime: null,
    ipAddress: "",
    direction: "any"
  };
  isFiltered.value = false;
  message.info("已清除筛选");
}

async function analyzeFile() {
  if (!filePath.value) return;
  try {
    isLoading.value = true;

    // 分析以太网数据包
    packets.value = await invoke("analyze_pcap", { filePath: filePath.value });

    // 分析IPv4数据包
    ipv4Packets.value = await invoke("analyze_ipv4_packets", { filePath: filePath.value });

    console.log("Packets:", packets.value);
    console.log("IPv4 Packets:", ipv4Packets.value);

    if (packets.value.length) {
      message.success(`成功加载 ${packets.value.length} 个以太网数据包，${ipv4Packets.value.length} 个 IPv4 数据包`);
    } else {
      message.warning("未找到数据包或无法解析文件");
    }

    // 重置筛选
    clearFilter();
  } catch (error) {
    message.error(`分析文件失败: ${error}`);
    console.error(error);
  } finally {
    isLoading.value = false;
  }
}
</script>

<template>
  <NConfigProvider>
    <NMessageProvider>
      <NLayout position="absolute" class="bg-gray-50">
        <NLayoutHeader bordered class="p-4 bg-white shadow-sm">
          <div class="text-2xl font-bold text-center text-green-600">KCPDump PCAP 分析器</div>
        </NLayoutHeader>
        <NLayoutContent class="p-6">
          <NCard class="max-w-4xl mx-auto">
            <NSpace vertical size="large" class="w-full">
              <!-- 文件选择器组件 -->
              <FileSelector v-model:filePath="filePath" :isLoading="isLoading" @analyze="analyzeFile" />

              <NDivider v-if="packets.length" />

              <div v-if="isLoading" class="text-center py-8">
                <div class="text-lg text-gray-600">加载中...</div>
              </div>

              <div v-else-if="packets.length">
                <NTabs v-model:value="activeTab">
                  <!-- 以太网数据包标签页 -->
                  <NTabPane name="ethernet" tab="以太网数据包">
                    <EthernetPacketsTable :packets="packets" />
                  </NTabPane>

                  <!-- IPv4数据包标签页 -->
                  <NTabPane name="ipv4" tab="IPv4 数据包">
                    <!-- IPv4筛选器组件 -->
                    <NCard title="IPv4 数据包筛选" class="mb-4">
                      <IPv4Filter v-model:filterData="ipv4Filter" :isFiltered="isFiltered"
                        :totalPackets="ipv4Packets.length" :filteredPackets="filteredIpv4Packets.length"
                        @apply="applyFilter" @clear="clearFilter" />
                    </NCard>

                    <!-- IPv4数据包表格组件 -->
                    <IPv4PacketsTable :packets="filteredIpv4Packets" :isFiltered="isFiltered"
                      :totalPackets="ipv4Packets.length" />
                  </NTabPane>

                  <!-- IP地址分布标签页 -->
                  <NTabPane name="statistics" tab="IP地址分布">
                    <NCard title="IPv4 地址分布统计" class="mb-4">
                      <IPAddressCharts :packets="filteredIpv4Packets" :isFiltered="isFiltered"
                        :totalPackets="ipv4Packets.length" />
                    </NCard>
                  </NTabPane>
                </NTabs>
              </div>

              <NEmpty v-else-if="filePath" description="未找到数据包或无法解析文件" class="py-8" />
            </NSpace>
          </NCard>
        </NLayoutContent>
      </NLayout>
    </NMessageProvider>
  </NConfigProvider>
</template>

<style>
/* 导入 Tailwind */
@import "tailwindcss";
</style>