import pandas as pd
import matplotlib.pyplot as plt
import io
import os

# 1. Load the raw CSV data
csv_data = """dim,N,algo,index_ms,trap_ms,query_ms,matched,range_pct,d,BQ,agg_ms,UQ,verify_ms,time_ms
vs_N,1000.0,BVCRSA,67536.08446200087,36.207031666587376,0.01980099962869038,45.0,,,,,,,
vs_N,1000.0,Trinity,147.39433500108134,18.566191332865856,8.325659333422664,1000.0,,,,,,,
vs_N,1000.0,ABSE-Range,842.15,12.35,4.21,136.0,,,,,,,
vs_N,1000.0,VC-KASE,441.97059299949615,0.35551933372820105,0.11467299979509941,136.0,,,,,,,
vs_N,1000.0,Latt-IBEKS,4.071025001394446,0.7142396668011012,0.12270666654027688,136.0,,,,,,,
vs_N,5000.0,BVCRSA,319968.47899800015,35.19491100026547,0.07657066635147203,232.0,,,,,,,
vs_N,5000.0,Trinity,616.7773390006914,19.74118266783383,43.48607133336676,5000.0,,,,,,,
vs_N,5000.0,ABSE-Range,4150.85,12.41,21.55,774.0,,,,,,,
vs_N,5000.0,VC-KASE,2253.4805619998224,0.354717999168012,0.5681960004343031,774.0,,,,,,,
vs_N,5000.0,Latt-IBEKS,20.412051000676,0.15424133259026954,0.5266940000486405,774.0,,,,,,,
vs_N,10000.0,BVCRSA,640376.9357260007,37.02608399968691,0.1737086671103801,558.0,,,,,,,
vs_N,10000.0,Trinity,1225.2570179989561,18.79252066646586,89.42011399994954,10000.0,,,,,,,
vs_N,10000.0,ABSE-Range,8310.22,12.45,43.12,1556.0,,,,,,,
vs_N,10000.0,VC-KASE,4510.29864100019,0.3467170002598626,1.1090206674756093,1556.0,,,,,,,
vs_N,10000.0,Latt-IBEKS,41.02010899987363,0.1203393324734255,1.1182880007254425,1556.0,,,,,,,
vs_N,20000.0,BVCRSA,1273664.7476960006,36.976283000209754,0.4720570001760886,1299.0,,,,,,,
vs_N,20000.0,Trinity,2502.078477999021,19.619990667100257,176.2046970003818,20000.0,,,,,,,
vs_N,20000.0,ABSE-Range,16520.40,12.50,86.40,3082.0,,,,,,,
vs_N,20000.0,VC-KASE,9095.34617799909,0.35104999975980417,2.5388216660455023,3082.0,,,,,,,
vs_N,20000.0,Latt-IBEKS,82.64035699903616,0.09020433390105609,2.247107332853678,3082.0,,,,,,,
vs_range,,BVCRSA,,36.13583866657185,0.04483533363478879,125.0,10.0,,,,,,
vs_range,,BVCRSA,,37.7882183335411,0.08523733352679604,196.0,20.0,,,,,,
vs_range,,BVCRSA,,36.655297000227925,0.10047133279537472,268.0,30.0,,,,,,
vs_range,,BVCRSA,,35.95379666694498,0.15304066740403263,417.0,50.0,,,,,,
vs_range,,BVCRSA,,35.616280666848375,0.2084766668607093,620.0,80.0,,,,,,
vs_range,,Trinity,,18.64533066630732,86.63350200004061,10000.0,10.0,,,,,,
vs_range,,Trinity,,19.233958666518447,88.14030766734504,10000.0,20.0,,,,,,
vs_range,,Trinity,,19.506938666988088,90.31894599987329,10000.0,30.0,,,,,,
vs_range,,Trinity,,18.775236665533157,86.30925299985392,10000.0,50.0,,,,,,
vs_range,,Trinity,,20.08323300045352,88.34325099996931,10000.0,80.0,,,,,,
vs_range,,ABSE-Range,,12.45,43.05,565.0,10.0,,,,,,
vs_range,,ABSE-Range,,12.42,43.20,1049.0,20.0,,,,,,
vs_range,,ABSE-Range,,12.48,43.15,1530.0,30.0,,,,,,
vs_range,,ABSE-Range,,12.44,43.10,2514.0,50.0,,,,,,
vs_range,,ABSE-Range,,12.46,43.18,4036.0,80.0,,,,,,
vs_range,,VC-KASE,,0.3546509997249814,1.1187220000768623,565.0,10.0,,,,,,
vs_range,,VC-KASE,,0.33741666690427036,0.8978776659205323,1049.0,20.0,,,,,,
vs_range,,VC-KASE,,0.3410500006187552,1.0697193332210493,1530.0,30.0,,,,,,
vs_range,,VC-KASE,,0.3464170004008338,1.2489949998174172,2514.0,50.0,,,,,,
vs_range,,VC-KASE,,0.3553843331853083,1.3277986666556292,4036.0,80.0,,,,,,
vs_range,,Latt-IBEKS,,0.1019046667352086,1.0775866661181983,565.0,10.0,,,,,,
vs_range,,Latt-IBEKS,,0.08277066566127662,0.8666093332673578,1049.0,20.0,,,,,,
vs_range,,Latt-IBEKS,,0.07860400000936352,0.9025779994165836,1530.0,30.0,,,,,,
vs_range,,Latt-IBEKS,,0.07140333339824186,1.42690366737952,2514.0,50.0,,,,,,
vs_range,,Latt-IBEKS,,0.10637200042159141,1.256295333102268,4036.0,80.0,,,,,,
vs_d,,BVCRSA,,38.188326333208046,0.04383533390258284,1.0,,1.0,,,,,
vs_d,,VC-KASE,,0.3566163334956703,2.9454716665592664,638.0,,1.0,,,,,
vs_d,,Latt-IBEKS,,0.10397166624898091,17.784433333266254,638.0,,1.0,,,,,
vs_d,,BVCRSA,,71.86302866648475,0.09240433367570706,1.0,,2.0,,,,,
vs_d,,VC-KASE,,0.3517830003450702,2.8778346671363884,0.0,,2.0,,,,,
vs_d,,Latt-IBEKS,,0.15164033296362808,17.387346999991376,0.0,,2.0,,,,,
vs_d,,BVCRSA,,110.90235499978007,0.11443866666619822,0.0,,3.0,,,,,
vs_d,,VC-KASE,,0.35214966677206877,3.0188746665468593,0.0,,3.0,,,,,
vs_d,,Latt-IBEKS,,0.11100533326195243,17.66319300016524,0.0,,3.0,,,,,
vs_d,,BVCRSA,,191.50692600063243,0.2516116655897349,0.0,,5.0,,,,,
vs_d,,VC-KASE,,0.47055566634905216,3.3861920001072576,0.0,,5.0,,,,,
vs_d,,Latt-IBEKS,,0.0970713329782787,18.878883334158065,0.0,,5.0,,,,,
vs_BQ,,BVCRSA,,,,,,,10.0,0.17437466582729635,,,
vs_BQ,,BVCRSA,,,,,,,50.0,0.9716786662465893,,,
vs_BQ,,BVCRSA,,,,,,,100.0,1.9950266663120904,,,
vs_BQ,,BVCRSA,,,,,,,500.0,10.505391333329802,,,
vs_BQ,,BVCRSA,,,,,,,1000.0,18.935685666898888,,,
vs_UQ,,BVCRSA,,,,,,,,,5.0,0.02500100041894863,
vs_UQ,,BVCRSA,,,,,,,,,10.0,0.05053566625671616,
vs_UQ,,BVCRSA,,,,,,,,,20.0,0.12880599994484024,
vs_UQ,,BVCRSA,,,,,,,,,50.0,0.42501999996602535,
vs_UQ,,BVCRSA,,,,,,,,,100.0,0.8584070001234068,
ablation_agg,,BVCRSA_Aggregate,,,,,,,10.0,,,,2.072151666652644
ablation_agg,,BVCRSA_Naive,,,,,,,10.0,,,,17.947077334004764
ablation_agg,,BVCRSA_Aggregate,,,,,,,50.0,,,,2.8477850003885883
ablation_agg,,BVCRSA_Naive,,,,,,,50.0,,,,88.42260966654673
ablation_agg,,BVCRSA_Aggregate,,,,,,,100.0,,,,4.069135667426356
ablation_agg,,BVCRSA_Naive,,,,,,,100.0,,,,174.95330700027503
ablation_agg,,BVCRSA_Aggregate,,,,,,,500.0,,,,13.259618000423265
ablation_agg,,BVCRSA_Naive,,,,,,,500.0,,,,884.3429003336496
ablation_agg,,BVCRSA_Aggregate,,,,,,,1000.0,,,,23.97059666691348
ablation_agg,,BVCRSA_Naive,,,,,,,1000.0,,,,1766.0629333337663
"""

# Read the CSV string into a Pandas DataFrame
df = pd.read_csv(io.StringIO(csv_data))

# Updated styling to match all algorithms
markers = {'BVCRSA': 'o', 'Trinity': '^', 'ABSE-Range': 'D', 'Latt-IBEKS': 's', 'VC-KASE': 'v'}
colors = {'BVCRSA': '#e31a1c', 'Trinity': '#33a02c', 'ABSE-Range': '#ff7f00', 'Latt-IBEKS': '#1f78b4', 'VC-KASE': '#6a3d9a'}

output_dir = "paper_figures"
os.makedirs(output_dir, exist_ok=True) 

# Ensure algorithms exist in mapping
algos_present = [a for a in markers.keys() if a in df['algo'].unique()]

# --- PLOT 1: Query vs N ---
plt.figure(figsize=(7, 5))
df_n = df[df['dim'] == 'vs_N'].sort_values(by='N')

# Define custom offsets for algorithms that cluster together
jitter_offsets = {
    'BVCRSA': 0.0,
    'ABSE-Range': 0.0,
    'Trinity': -0.04,
    'Latt-IBEKS': 0.0,
    'VC-KASE': 0.04
}

for algo in algos_present:
    subset = df_n[df_n['algo'] == algo]
    if not subset.empty:
        jittered_x = subset['N'] * (1 + jitter_offsets.get(algo, 0.0))
        
        is_clustered = algo in ['Trinity', 'Latt-IBEKS', 'VC-KASE']
        face_color = 'none' if is_clustered else colors[algo]
        line_alpha = 0.7 if is_clustered else 1.0 
        
        plt.plot(jittered_x, subset['query_ms'], 
                 marker=markers[algo], 
                 color=colors[algo], 
                 linewidth=2, 
                 markersize=9, 
                 markerfacecolor=face_color, 
                 markeredgewidth=2, 
                 alpha=line_alpha,
                 linestyle='--', 
                 label=algo)

plt.yscale('log')
plt.xticks([1000, 5000, 10000, 20000], ['1K', '5K', '10K', '20K']) 

plt.title('Query Processing Time vs Database Size', fontsize=12, fontweight='bold')
plt.xlabel('Number of Records (N)', fontsize=11, fontweight='bold')
plt.ylabel('Query Processing Time (ms)', fontsize=11, fontweight='bold')
plt.grid(True, linestyle='--', alpha=0.5)
plt.legend()
plt.tight_layout()
plt.savefig(os.path.join(output_dir, "fig_query_vs_N.png"), dpi=300, bbox_inches='tight')
plt.close()

# --- PLOT 2: Trapdoor vs N ---
plt.figure(figsize=(7, 5))

for algo in algos_present:
    subset = df_n[df_n['algo'] == algo]
    if not subset.empty and subset['trap_ms'].sum() > 0:
        jittered_x = subset['N'] * (1 + jitter_offsets.get(algo, 0.0))
        
        is_clustered = algo in ['Trinity', 'Latt-IBEKS', 'VC-KASE']
        face_color = 'none' if is_clustered else colors[algo]
        line_alpha = 0.7 if is_clustered else 1.0 
        
        plt.plot(jittered_x, subset['trap_ms'], 
                 marker=markers[algo], 
                 color=colors[algo], 
                 linewidth=2, 
                 markersize=9, 
                 markerfacecolor=face_color, 
                 markeredgewidth=2,
                 alpha=line_alpha,
                 linestyle='--', 
                 label=algo)

plt.yscale('log')
plt.xticks([1000, 5000, 10000, 20000], ['1K', '5K', '10K', '20K'])

plt.title('Trapdoor Generation Time vs Database Size', fontsize=12, fontweight='bold')
plt.xlabel('Number of Records (N)', fontsize=11, fontweight='bold')
plt.ylabel('Trapdoor Generation Time (ms)', fontsize=11, fontweight='bold')
plt.grid(True, linestyle='--', alpha=0.5)
plt.legend()
plt.tight_layout()
plt.savefig(os.path.join(output_dir, "fig_trapdoor_vs_N.png"), dpi=300, bbox_inches='tight')
plt.close()

# --- PLOT 3: Index Generation vs N ---
plt.figure(figsize=(7, 5))
for algo in algos_present:
    subset = df_n[df_n['algo'] == algo]
    if not subset.empty and subset['index_ms'].sum() > 0:
        plt.plot(subset['N'], subset['index_ms'], marker=markers[algo], color=colors[algo], 
                 linewidth=2, markersize=8, linestyle='--', label=algo)
plt.yscale('log')
plt.title('Index Generation Time vs Database Size', fontsize=12, fontweight='bold')
plt.xlabel('Number of Records (N)', fontsize=11, fontweight='bold')
plt.ylabel('Index Build Time (ms) [Log Scale]', fontsize=11, fontweight='bold')
plt.grid(True, linestyle='--', alpha=0.5)
plt.legend()
plt.tight_layout()
plt.savefig(os.path.join(output_dir, "fig_index_vs_N.png"), dpi=300, bbox_inches='tight')
plt.close()

# --- PLOT 4: Query vs Range Width ---
plt.figure(figsize=(7, 5))
df_range = df[df['dim'] == 'vs_range'].sort_values(by='range_pct')
for algo in algos_present:
    subset = df_range[df_range['algo'] == algo]
    subset = subset[subset['query_ms'] > 0] 
    if not subset.empty:
        plt.plot(subset['range_pct'], subset['query_ms'], marker=markers[algo], color=colors[algo], 
                 linewidth=2, markersize=8, linestyle='--', label=algo)
plt.yscale('log')
plt.title('Query Processing Time vs Range Width', fontsize=12, fontweight='bold')
plt.xlabel('Range Size (% of domain)', fontsize=11, fontweight='bold')
plt.ylabel('Query Processing Time (ms)', fontsize=11, fontweight='bold')
plt.grid(True, linestyle='--', alpha=0.5)
plt.legend()
plt.tight_layout()
plt.savefig(os.path.join(output_dir, "fig_query_vs_range.png"), dpi=300, bbox_inches='tight')
plt.close()

# --- PLOT 5: Conjunctive Query Time vs d ---
plt.figure(figsize=(7, 5))
df_d = df[df['dim'] == 'vs_d'].sort_values(by='d')

# Latt-IBEKS explicitly added to the loop
for algo in ['BVCRSA', 'VC-KASE', 'Latt-IBEKS']: 
    if algo in algos_present:
        subset = df_d[df_d['algo'] == algo]
        if not subset.empty:
            plt.plot(subset['d'], subset['query_ms'], marker=markers[algo], color=colors[algo], 
                     linewidth=2, markersize=8, linestyle='--', label=algo)

# Y-axis changed to log scale to accommodate Latt-IBEKS
plt.yscale('log') 

plt.title('Conjunctive Query Time vs Keywords (d)', fontsize=12, fontweight='bold')
plt.xlabel('Number of Query Dimensions / Keywords (d)', fontsize=11, fontweight='bold')
plt.ylabel('Query Processing Time (ms) [Log Scale]', fontsize=11, fontweight='bold')
plt.grid(True, linestyle='--', alpha=0.5)
plt.legend()
plt.tight_layout()
plt.xticks([1, 2, 3, 5])
plt.savefig(os.path.join(output_dir, "fig_query_vs_d_conjunctive.png"), dpi=300, bbox_inches='tight')
plt.close()

# --- PLOT 6: Aggregation vs BQ ---
plt.figure(figsize=(7, 5))
df_bq = df[df['dim'] == 'vs_BQ'].sort_values(by='BQ')
if 'BVCRSA' in algos_present:
    subset = df_bq[df_bq['algo'] == 'BVCRSA']
    if not subset.empty:
        plt.plot(subset['BQ'], subset['agg_ms'], marker=markers['BVCRSA'], color=colors['BVCRSA'], 
                 linewidth=2, markersize=8, linestyle='--', label='BVCRSA (EC-ElGamal)')
plt.title('Homomorphic Aggregation Time vs |BQ|', fontsize=12, fontweight='bold')
plt.xlabel('Number of Matched Nodes |BQ|', fontsize=11, fontweight='bold')
plt.ylabel('Aggregation Time (ms)', fontsize=11, fontweight='bold')
plt.grid(True, linestyle='--', alpha=0.5)
plt.legend()
plt.tight_layout()
plt.savefig(os.path.join(output_dir, "fig_agg_vs_BQ.png"), dpi=300, bbox_inches='tight')
plt.close()

# --- PLOT 7: Ablation Study ---
# --- PLOT 7: Ablation Study ---
plt.figure(figsize=(8, 6))

df_ablation = df[df['dim'] == 'ablation_agg'].sort_values(by='BQ')

subset_naive = df_ablation[df_ablation['algo'] == 'BVCRSA_Naive']
if not subset_naive.empty:
    plt.plot(subset_naive['BQ'], subset_naive['time_ms'], 
             marker='s', color='#1f78b4', linewidth=2.5, markersize=10, 
             linestyle='--', label='Naive BVCRSA (No Aggregation)')

subset_agg = df_ablation[df_ablation['algo'] == 'BVCRSA_Aggregate']
if not subset_agg.empty:
    plt.plot(subset_agg['BQ'], subset_agg['time_ms'], 
             marker='o', color='#e31a1c', linewidth=2.5, markersize=10, 
             linestyle='-', label='BVCRSA (With Homomorphic Aggregation)')

plt.title('Ablation Study: Impact of Homomorphic Aggregation', fontsize=14, fontweight='bold')
plt.xlabel('Number of Matched Nodes |BQ|', fontsize=12, fontweight='bold')
plt.ylabel('Total Processing Time (ms)', fontsize=12, fontweight='bold')

plt.grid(True, linestyle='--', alpha=0.6)
plt.legend(fontsize=12, loc='upper left')

# Explicitly lock both the X and Y axes to crop out the BQ=1000 outlier
plt.xlim(-20, 520)
plt.ylim(-40, 950) 

plt.tight_layout()
plt.savefig(os.path.join(output_dir, "fig_ablation_aggregation.png"), dpi=300, bbox_inches='tight')
plt.close()

print("All 7 definitive figures saved successfully!")