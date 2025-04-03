<script setup lang="ts">
import { open } from "@tauri-apps/plugin-dialog";
import { NButton, NInput } from "naive-ui";

const props = defineProps<{
  filePath: string;
  isLoading: boolean;
}>();

const emit = defineEmits<{
  (e: 'update:filePath', value: string): void;
  (e: 'analyze'): void;
}>();

async function pickFile() {
  const selected = await open({
    filters: [{ name: "PCAP Files", extensions: ["pcap"] }],
  });
  
  if (selected && typeof selected === "string") {
    emit('update:filePath', selected);
    emit('analyze');
  }
}
</script>

<template>
  <div class="flex items-center space-x-4">
    <NButton type="primary" @click="pickFile" :loading="props.isLoading">
      选择 PCAP 文件
    </NButton>
    <NInput
      v-if="props.filePath"
      :value="props.filePath"
      readonly
      placeholder="未选择文件"
      class="flex-grow"
    />
  </div>
</template>
