#!/bin/bash

# Tamanho alvo
largura_alvo=1920
altura_alvo=998

# Offset para cortar do topo (removendo 82px de cima)
offset_x=0
offset_y=82

# Pasta de saída
mkdir -p cortadas

# Loop por cada PNG
for img in *.png; do
    echo "✂️ Cortando do topo: $img -> ${largura_alvo}x${altura_alvo}"
    convert "$img" -crop ${largura_alvo}x${altura_alvo}+${offset_x}+${offset_y} +repage "cortadas/$img"
done

echo "✅ Corte concluído! Arquivos salvos em ./cortadas"
