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
  NTabs,
  NTabPane,
  NDatePicker,
  NSelect,
  NInputGroup,
  NForm,
  NFormItem,
} from "naive-ui";

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

const currentPage = ref(1);
const packetsPerPage = ref(5);
const ipv4CurrentPage = ref(1);
const ipv4PacketsPerPage = ref(5);

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

const paginatedPackets = computed(() => {
  const start = (currentPage.value - 1) * packetsPerPage.value;
  const end = start + packetsPerPage.value;
  return packets.value.slice(start, end);
});

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

const paginatedIpv4Packets = computed(() => {
  const start = (ipv4CurrentPage.value - 1) * ipv4PacketsPerPage.value;
  const end = start + ipv4PacketsPerPage.value;
  return filteredIpv4Packets.value.slice(start, end);
});

const totalPages = computed(() => {
  return Math.ceil(packets.value.length / packetsPerPage.value);
});

const totalIpv4Pages = computed(() => {
  return Math.ceil(filteredIpv4Packets.value.length / ipv4PacketsPerPage.value);
});

function handlePageChange(page: number) {
  currentPage.value = page;
}

function handlePageSizeChange(pageSize: number) {
  packetsPerPage.value = pageSize;
  currentPage.value = 1;
}

function handleIpv4PageChange(page: number) {
  ipv4CurrentPage.value = page;
}

function handleIpv4PageSizeChange(pageSize: number) {
  ipv4PacketsPerPage.value = pageSize;
  ipv4CurrentPage.value = 1;
}

function applyFilter() {
  isFiltered.value = true;
  ipv4CurrentPage.value = 1;
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
  ipv4CurrentPage.value = 1;
  message.info("已清除筛选");
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

// 协议映射
const protocolMap: { [key: number]: string } = {
  1: "ICMP",
  2: "IGMP",
  6: "TCP",
  17: "UDP",
  89: "OSPF"
};

// 获取协议名称
const getProtocolName = (protocolNum: number): string => {
  return protocolMap[protocolNum] || `未知(${protocolNum})`;
};

// format timestamp
const formatTimestamp = (tsSec: number, tsUsec: number, format: string = 'default') => {
  const date = new Date(tsSec * 1000 + Math.floor(tsUsec / 1000));
  
  // 添加微秒部分（JavaScript Date 只支持到毫秒）
  const microseconds = tsUsec % 1000;
  
  switch (format) {
    case 'full':
      return `${date.toISOString().replace('Z', '')}${microseconds.toString().padStart(3, '0')}`;
    case 'time':
      return `${date.toLocaleTimeString()}.${(tsUsec / 1000).toFixed(3)}`;
    default:
      return `${date.toLocaleString()}.${(tsUsec / 1000).toFixed(3)}`;
  }
};

// 创建以太网表格列
const columns = [
  {
    title: "时间戳",
    key: "timestamp",
    width: 200,
    render: (row: { tsSec: number; tsUsec: number }) => {
      return h('div', {}, formatTimestamp(row.tsSec, row.tsUsec));
    }
  },
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

// 创建IPv4表格列
const ipv4Columns = [
  {
    title: "时间戳",
    key: "timestamp",
    width: 200,
    render: (row: { tsSec: number; tsUsec: number }) => {
      return h('div', {}, formatTimestamp(row.tsSec, row.tsUsec));
    }
  },
  {
    title: "源IP",
    key: "sourceIp",
  },
  {
    title: "目标IP",
    key: "destIp",
  },
  {
    title: "协议",
    key: "protocol",
    render: (row: { protocol: number }) => {
      return h(NTag, { type: "success", bordered: false }, { 
        default: () => getProtocolName(row.protocol) 
      });
    }
  },
  {
    title: "TTL",
    key: "ttl",
  },
  {
    title: "总长度",
    key: "totalLength",
  },
];

// IP方向选项
const directionOptions = [
  { label: "任意", value: "any" },
  { label: "源IP", value: "source" },
  { label: "目标IP", value: "dest" },
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
              <NTabs v-model:value="activeTab">
                <NTabPane name="ethernet" tab="以太网数据包">
                  <NDataTable
                    :columns="columns"
                    :data="paginatedPackets"
                    :bordered="false"
                    :single-line="false"
                    class="mb-4"
                  />
                  
                  <div class="flex justify-between items-center mt-4">
                    <div class="text-sm text-gray-500">
                      共 {{ packets.length }} 个以太网数据包
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
                </NTabPane>
                
                <NTabPane name="ipv4" tab="IPv4 数据包">
                  <!-- 筛选区域 -->
                  <NCard title="IPv4 数据包筛选" class="mb-4">
                    <NForm inline>
                      <NFormItem label="时间范围" class="mt-2">
                        <NDatePicker
                          v-model:value="ipv4Filter.startTime"
                          type="datetime"
                          placeholder="开始时间"
                          clearable
                          :shortcuts="{ now: Date.now() }"
                          style="width: 210px"
                        />
                        <span class="mx-2">至</span>
                        <NDatePicker
                          v-model:value="ipv4Filter.endTime"
                          type="datetime"
                          placeholder="结束时间"
                          clearable
                          :shortcuts="{ now: Date.now() }"
                          style="width: 210px"
                        />
                      </NFormItem>
                      
                      <NFormItem label="IP筛选" class="mt-2">
                        <NInputGroup>
                          <NSelect
                            v-model:value="ipv4Filter.direction"
                            :options="directionOptions"
                            style="width: 100px"
                          />
                          <NInput
                            v-model:value="ipv4Filter.ipAddress"
                            placeholder="输入要筛选的IP"
                            style="width: 200px"
                          />
                        </NInputGroup>
                      </NFormItem>

                      <NFormItem class="mt-2">
                        <NButton type="primary" @click="applyFilter">应用筛选</NButton>
                        <NButton type="default" class="ml-2" @click="clearFilter">清除筛选</NButton>
                      </NFormItem>
                    </NForm>

                    <div v-if="isFiltered" class="text-sm text-blue-600 mt-2">
                      <NTag type="info">
                        已筛选：显示 {{ filteredIpv4Packets.length }} / {{ ipv4Packets.length }} 个数据包
                      </NTag>
                    </div>
                  </NCard>
                  
                  <!-- 数据表格 -->
                  <NDataTable
                    :columns="ipv4Columns"
                    :data="paginatedIpv4Packets"
                    :bordered="false"
                    :single-line="false"
                    class="mb-4"
                  />
                  
                  <div class="flex justify-between items-center mt-4">
                    <div class="text-sm text-gray-500">
                      {{ isFiltered ? `显示 ${filteredIpv4Packets.length} / ${ipv4Packets.length} 个 IPv4 数据包` : `共 ${ipv4Packets.length} 个 IPv4 数据包` }}
                    </div>
                    <NPagination
                      v-model:page="ipv4CurrentPage"
                      v-model:page-size="ipv4PacketsPerPage"
                      :page-count="totalIpv4Pages"
                      :page-sizes="[5, 10, 20, 50, 100]"
                      show-size-picker
                      @update:page="handleIpv4PageChange"
                      @update:page-size="handleIpv4PageSizeChange"
                    />
                  </div>
                </NTabPane>
              </NTabs>
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