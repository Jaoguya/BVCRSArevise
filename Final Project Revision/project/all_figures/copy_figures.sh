#!/bin/bash
# Copy all project figures into this consolidated folder
DIR="$(cd "$(dirname "$0")" && pwd)"
PROJ="$(dirname "$DIR")"

# Benchmark figures from project root
cp "$PROJ"/fig2_trap_vs_N.png "$DIR/" 2>/dev/null
cp "$PROJ"/fig3_trap_vs_range.png "$DIR/" 2>/dev/null
cp "$PROJ"/fig4_trap_vs_keywords.png "$DIR/" 2>/dev/null
cp "$PROJ"/fig5_query_vs_N.png "$DIR/" 2>/dev/null
cp "$PROJ"/fig6_query_vs_range.png "$DIR/" 2>/dev/null
cp "$PROJ"/fig7_index_vs_N.png "$DIR/" 2>/dev/null

# Figures from added_paper (6-model comparison)
cp "$PROJ"/added_paper/fig2_trap_vs_N.png "$DIR/added_fig2_trap_vs_N.png" 2>/dev/null
cp "$PROJ"/added_paper/fig3_trap_vs_range.png "$DIR/added_fig3_trap_vs_range.png" 2>/dev/null
cp "$PROJ"/added_paper/fig4_trap_vs_keywords.png "$DIR/added_fig4_trap_vs_keywords.png" 2>/dev/null
cp "$PROJ"/added_paper/fig5_query_vs_N.png "$DIR/added_fig5_query_vs_N.png" 2>/dev/null
cp "$PROJ"/added_paper/fig6_query_vs_range.png "$DIR/added_fig6_query_vs_range.png" 2>/dev/null
cp "$PROJ"/added_paper/fig7_index_vs_N.png "$DIR/added_fig7_index_vs_N.png" 2>/dev/null

# N=512 figures
cp "$PROJ"/added_paper/n512_fig*.png "$DIR/" 2>/dev/null

# Additional images
cp "$PROJ"/added_paper/image.png "$DIR/" 2>/dev/null

echo "All figures copied to $DIR"
ls -la "$DIR"/*.png 2>/dev/null | wc -l
echo "total PNG files"
