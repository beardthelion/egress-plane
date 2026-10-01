<template><div>{{ msg }}</div></template>
<script>
export default { mounted() { fetch("https://api.example.com/vue"); } };
</script>
