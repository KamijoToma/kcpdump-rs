<script setup lang="ts">
import { ref, computed } from "vue";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";

const filePath = ref("");
const packets = ref<{ ethType: string; source: string; target: string }[]>([]);

const currentPage = ref(1);
const packetsPerPage = 10;

const paginatedPackets = computed(() => {
  const start = (currentPage.value - 1) * packetsPerPage;
  const end = start + packetsPerPage;
  return packets.value.slice(start, end);
});

const totalPages = computed(() => {
  return Math.ceil(packets.value.length / packetsPerPage);
});

function nextPage() {
  if (currentPage.value < totalPages.value) {
    currentPage.value++;
  }
}

function prevPage() {
  if (currentPage.value > 1) {
    currentPage.value--;
  }
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
  packets.value = await invoke("analyze_pcap", { filePath: filePath.value });
  console.log("Packets:", packets.value);
}
</script>

<template>
  <main class="container">
    <h1>PCAP File Analyzer</h1>

    <button @click="pickFile">Pick a PCAP File</button>
    <p v-if="filePath">Selected File: {{ filePath }}</p>

    <table v-if="packets.length" class="packet-table">
      <thead>
        <tr>
          <th>Type</th>
          <th>Source</th>
          <th>Target</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="(packet, index) in paginatedPackets" :key="index">
          <td>{{ packet.ethType }}</td>
          <td>{{ packet.source }}</td>
          <td>{{ packet.target }}</td>
        </tr>
      </tbody>
    </table>

    <div v-if="packets.length" class="pagination">
      <button @click="prevPage" :disabled="currentPage === 1">Previous</button>
      <span>Page {{ currentPage }} of {{ totalPages }}</span>
      <button @click="nextPage" :disabled="currentPage === totalPages">Next</button>
    </div>

    <p v-else-if="filePath">No packets found or unable to analyze the file.</p>
  </main>
</template>

<style scoped>
.packet-table {
  margin: 20px auto;
  border-collapse: collapse;
  width: 80%;
}

.packet-table th,
.packet-table td {
  border: 1px solid #ddd;
  padding: 8px;
  text-align: center;
}

.packet-table th {
  background-color: #f4f4f4;
  font-weight: bold;
}

.pagination {
  display: flex;
  justify-content: center;
  align-items: center;
  margin-top: 20px;
}

.pagination button {
  margin: 0 10px;
  padding: 5px 10px;
  cursor: pointer;
}

.pagination button:disabled {
  cursor: not-allowed;
  opacity: 0.5;
}
</style>