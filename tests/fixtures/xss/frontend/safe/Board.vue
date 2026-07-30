<!-- 골든셋 안전 픽스처 (xss/frontend): DOMPurify.sanitize 래핑 + 텍스트 보간 → 후보 0. -->
<template>
  <div class="board-view">
    <h1>{{ post.title }}</h1>
    <div v-html="DOMPurify.sanitize(post.content)"></div>
    <p>{{ post.summary }}</p>
  </div>
</template>

<script setup>
import DOMPurify from 'dompurify'
const route = useRoute()
const { data: post } = await useFetch(`/api/v1/boards/${route.params.id}`)
</script>
