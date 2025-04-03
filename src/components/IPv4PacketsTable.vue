<script setup lang="ts">
import { ref, computed, h } from "vue";
import { NDataTable, NPagination, NTag } from "naive-ui";

const props = defineProps<{
  packets: {
    sourceIp: string;
    destIp: string;
    protocol: number;
    ttl: number;
    tsSec: number;
    tsUsec: number;
    totalLength: number;
  }[];
  isFiltered: boolean;
  totalPackets: number;
}>();

const currentPage = ref(1);
const packetsPerPage = ref(5);

const paginatedPackets = computed(() => {
  const start = (currentPage.value - 1) * packetsPerPage.value;
  const end = start + packetsPerPage.value;
  return props.packets.slice(start, end);
});

const totalPages = computed(() => {
  return Math.ceil(props.packets.length / packetsPerPage.value);
});

function handlePageChange(page: number) {
  currentPage.value = page;
}

function handlePageSizeChange(pageSize: number) {
  packetsPerPage.value = pageSize;
  currentPage.value = 1;
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
</script>

<template>
  <div>
    <NDataTable
      :columns="ipv4Columns"
      :data="paginatedPackets"
      :bordered="false"
      :single-line="false"
      class="mb-4"
    />
    
    <div class="flex justify-between items-center mt-4">
      <div class="text-sm text-gray-500">
        {{ isFiltered ? `显示 ${packets.length} / ${totalPackets} 个 IPv4 数据包` : `共 ${packets.length} 个 IPv4 数据包` }}
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
</template>
