<script setup lang="ts">
import { NButton, NForm, NFormItem, NDatePicker, NSelect, NInput, NInputGroup, NTag } from "naive-ui";

const props = defineProps<{
  isFiltered: boolean;
  filterData: {
    startTime: number | null;
    endTime: number | null;
    ipAddress: string;
    direction: string;
  };
  totalPackets: number;
  filteredPackets: number;
}>();

const emit = defineEmits<{
  (e: 'update:filterData', value: any): void;
  (e: 'apply'): void;
  (e: 'clear'): void;
}>();

// IP方向选项
const directionOptions = [
  { label: "任意", value: "any" },
  { label: "源IP", value: "source" },
  { label: "目标IP", value: "dest" },
];

function updateFilter(key: string, value: any) {
  const newFilter = { ...props.filterData, [key]: value };
  emit('update:filterData', newFilter);
}

function applyFilter() {
  emit('apply');
}

function clearFilter() {
  emit('clear');
}
</script>

<template>
  <NForm inline>
    <NFormItem label="时间范围" class="mt-2">
      <NDatePicker
        :value="filterData.startTime"
        @update:value="value => updateFilter('startTime', value)"
        type="datetime"
        placeholder="开始时间"
        clearable
        :shortcuts="{ now: Date.now() }"
        style="width: 210px"
      />
      <span class="mx-2">至</span>
      <NDatePicker
        :value="filterData.endTime"
        @update:value="value => updateFilter('endTime', value)"
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
          :value="filterData.direction"
          @update:value="value => updateFilter('direction', value)"
          :options="directionOptions"
          style="width: 100px"
        />
        <NInput
          :value="filterData.ipAddress"
          @update:value="value => updateFilter('ipAddress', value)"
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
      已筛选：显示 {{ filteredPackets }} / {{ totalPackets }} 个数据包
    </NTag>
  </div>
</template>
