<!-- 골든셋 취약 픽스처 (xss/frontend): 서버에서 온 게시글 본문을 v-html로 그대로 렌더 → 저장형 XSS. -->
<template>
  <div class="board-view">
    <h1>{{ post.title }}</h1>
    <div v-html="post.content"></div>
  </div>
</template>

<script setup>
const route = useRoute()
const { data: post } = await useFetch(`/api/v1/boards/${route.params.id}`)
</script>
