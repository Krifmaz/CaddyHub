<script>
  // Colored initial for a site, stable per name.
  let { name = '', size = 36 } = $props()
  const palette = ['#0e9f6e', '#2563eb', '#7c3aed', '#db2777', '#ea580c', '#0891b2', '#4f46e5', '#ca8a04', '#059669', '#9333ea']
  const color = $derived.by(() => {
    let h = 0
    for (const c of name) h = (h * 31 + c.charCodeAt(0)) >>> 0
    return palette[h % palette.length]
  })
  const letter = $derived((name.replace(/^(https?:\/\/|www\.)/, '').match(/[a-z0-9]/i)?.[0] || '?').toUpperCase())
</script>

<span class="avatar" style="width:{size}px;height:{size}px;font-size:{Math.round(size * 0.4)}px;background:linear-gradient(135deg, {color}, color-mix(in srgb, {color} 70%, #000))">{letter}</span>
