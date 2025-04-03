<script setup lang="ts">
import { ref, computed, h } from "vue";
import { NDataTable, NPagination, NTag } from "naive-ui";

const props = defineProps<{
  packets: {
    ethType: string;
    source: string;
    target: string;
    tsSec: number;
    tsUsec: number;
  }[];
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

// 格式化时间戳
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
</script>

<template>
  <div>
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
  </div>
</template>
