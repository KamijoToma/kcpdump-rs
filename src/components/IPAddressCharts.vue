<script setup lang="ts">
import { ref, computed, onMounted, watch } from "vue";
import * as echarts from 'echarts';
import { NGrid, NGridItem, NEmpty } from "naive-ui";

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

// IP地址分布图表引用
const sourceIpChartRef = ref<HTMLElement | null>(null);
const destIpChartRef = ref<HTMLElement | null>(null);
let sourceIpChart: echarts.ECharts | null = null;
let destIpChart: echarts.ECharts | null = null;

// IP地址统计数据
const sourceIpStats = computed(() => {
  const stats: Record<string, number> = {};
  props.packets.forEach(packet => {
    const ip = packet.sourceIp;
    stats[ip] = (stats[ip] || 0) + 1;
  });
  return Object.entries(stats).map(([ip, count]) => ({
    name: ip,
    value: count,
    percentage: ((count / props.packets.length) * 100).toFixed(2)
  })).sort((a, b) => b.value - a.value);
});

const destIpStats = computed(() => {
  const stats: Record<string, number> = {};
  props.packets.forEach(packet => {
    const ip = packet.destIp;
    stats[ip] = (stats[ip] || 0) + 1;
  });
  return Object.entries(stats).map(([ip, count]) => ({
    name: ip,
    value: count,
    percentage: ((count / props.packets.length) * 100).toFixed(2)
  })).sort((a, b) => b.value - a.value);
});

// 初始化图表
function initCharts() {
  if (sourceIpChartRef.value) {
    sourceIpChart = echarts.init(sourceIpChartRef.value);
  }
  if (destIpChartRef.value) {
    destIpChart = echarts.init(destIpChartRef.value);
  }
  updateCharts();
}

// 更新图表数据
function updateCharts() {
  if (sourceIpChart && props.packets.length > 0) {
    sourceIpChart.setOption({
      title: {
        text: '源IP地址分布',
        left: 'center'
      },
      tooltip: {
        trigger: 'item',
        formatter: '{a} <br/>{b}: {c} ({d}%)'
      },
      legend: {
        orient: 'vertical',
        left: 'left',
        type: 'scroll',
        formatter: (name: string) => {
          const item = sourceIpStats.value.find(item => item.name === name);
          return `${name} (${item?.percentage}%)`;
        }
      },
      series: [
        {
          name: '源IP',
          type: 'pie',
          radius: '60%',
          data: sourceIpStats.value,
          emphasis: {
            itemStyle: {
              shadowBlur: 10,
              shadowOffsetX: 0,
              shadowColor: 'rgba(0, 0, 0, 0.5)'
            }
          }
        }
      ]
    });
  }

  if (destIpChart && props.packets.length > 0) {
    destIpChart.setOption({
      title: {
        text: '目标IP地址分布',
        left: 'center'
      },
      tooltip: {
        trigger: 'item',
        formatter: '{a} <br/>{b}: {c} ({d}%)'
      },
      legend: {
        orient: 'vertical',
        left: 'left',
        type: 'scroll',
        formatter: (name: string) => {
          const item = destIpStats.value.find(item => item.name === name);
          return `${name} (${item?.percentage}%)`;
        }
      },
      series: [
        {
          name: '目标IP',
          type: 'pie',
          radius: '60%',
          data: destIpStats.value,
          emphasis: {
            itemStyle: {
              shadowBlur: 10,
              shadowOffsetX: 0,
              shadowColor: 'rgba(0, 0, 0, 0.5)'
            }
          }
        }
      ]
    });
  }
}

// 监听数据变化并更新图表
watch(
  () => props.packets,
  () => {
    if (!sourceIpChart || !destIpChart) {
      initCharts();
    } else {
      updateCharts();
    }
  },
  { deep: true }
);

// 监听窗口大小变化，重绘图表
window.addEventListener('resize', () => {
  if (sourceIpChart) sourceIpChart.resize();
  if (destIpChart) destIpChart.resize();
});

// 图表加载后初始化
onMounted(() => {
  initCharts();
});
</script>

<template>
  <div>
    <div v-if="packets.length > 0">
      <NGrid :cols="1" :x-gap="12" :y-gap="12">
        <NGridItem>
          <div ref="sourceIpChartRef" style="height: 400px;"></div>
        </NGridItem>
        <NGridItem>
          <div ref="destIpChartRef" style="height: 400px;"></div>
        </NGridItem>
      </NGrid>
      
      <div class="mt-4 text-sm text-gray-600">
        <p>* 图表基于当前筛选后的 {{ packets.length }} 个 IPv4 数据包</p>
        <p v-if="isFiltered" class="mt-1">
          * 你可以在 IPv4 数据包标签页中调整筛选条件
        </p>
      </div>
    </div>
    <NEmpty 
      v-else
      description="没有可用的 IPv4 数据包"
      class="py-8"
    />
  </div>
</template>
