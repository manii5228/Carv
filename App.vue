<template>
  <div id="app">
    <router-view />
  </div>
</template>

<script setup>
// no script needed yet
</script>

<style>
/* Apply Biscotti font */
@font-face {
  font-family: 'Biscotti';
  src: url('./assets/biscotti.ttf') format('truetype');
}
body {
  margin: 0;
  font-family: 'Biscotti', sans-serif;
  background: #f9f9f9;
}
</style>
