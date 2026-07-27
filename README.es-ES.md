# jeprofl

jeprofl es una herramienta de perfilado de asignación de memoria que utiliza la tecnología eBPF para analizar las asignaciones de jemalloc en su programa. Es posible que funcione con otros asignadores, pero esto no ha sido probado.

[![colorized flamegraph output](assets/flamegraph.png)](assets/flamegraph.svg)

Puede utilizarse con un programa que ya esté en ejecución sin necesidad de recompilación. El overhead con un muestreo de 1000x es de 80 ns por llamada bajo 2.5M de asignaciones por segundo.
![bpftop.png](assets/bpftop.png)

## Características

- Adjuntarse a un proceso o programa específico
- Soporte para varias funciones de asignación de jemalloc (malloc, calloc, realloc, etc.)
- Ordenar los resultados por recuento de asignaciones o tráfico total de memoria
- Establecer tamaños de asignación mínimos y máximos para rastrear
- Muestreo de eventos configurable
- Generar salida CSV y flame graphs
- Rastreo de histogramas de asignación por traza de pila (redondeados a potencia de 2)

```
6ae5a0 - malloc
4e54b0 - uu_ls::enter_directory
4e54b0 - uu_ls::enter_directory
4e54b0 - uu_ls::enter_directory
4e54b0 - uu_ls::enter_directory
4db790 - uu_ls::list
23b070 - uu_ls::uumain
bb560  - coreutils::main
1c9e60 - std::sys::backtrace::__rust_begin_short_backtrace
bdf00  - main
2a010  - __libc_start_call_main
2a0c0  - __libc_start_main_alias_2
a7f00  - _start

-----------+-----------+------------+--------------------------------------------------
Size       | Count     | Percentage | Distribution
-----------+-----------+------------+--------------------------------------------------
1 B        |     16870 |      4.23% | #######
2 B        |     21716 |      5.44% | #########
4 B        |     38150 |      9.56% | ################
8 B        |    120776 |     30.27% | ##################################################
16 B       |    103586 |     25.97% | ###########################################
32 B       |     58988 |     14.79% | ########################
64 B       |      7444 |      1.87% | ###
128 B      |     14768 |      3.70% | ######
512 B      |     16638 |      4.17% | #######
Total allocations: 18.4 MiB in 398936 allocations
```

- Overhead mínimo

## Limitaciones

- Solo funciona con programas enlazados estáticamente (por ahora). Puede funcionar con programas enlazados dinámicamente, pero debe proporcionar la ruta a la dylib.

## Prrequisitos

1. Instalar bpf-linker: `cargo install bpf-linker`
2. Kernel de Linux con soporte para eBPF
3. Privilegios de root (para adjuntarse a procesos)

## Uso

Opciones:

- `--pid <PID>`: Adjuntarse a un ID de proceso específico
- `--function <FUNCTION>`: Especificar la función de jemalloc a rastrear (por defecto: malloc)
- `--order-by <ORDER>`: Ordenar los resultados por 'count' o 'traffic' (por defecto: traffic). Traffic es el tamaño total asignado, count es el número de llamadas a malloc.
- `--max-alloc-size <SIZE>`: Tamaño máximo de asignación a rastrear
- `--min-alloc-size <SIZE>`: Tamaño mínimo de asignación a rastrear
- `--sample-every <N>`: Muestrear cada N evento
- `--skip-size <SIZE>`: Omitir asignaciones con un total asignado < SIZE bytes
- `--skip-count <COUNT>`: Omitir trazas de pila con un recuento total de asignaciones < COUNT
- `--csv <PATH>`: Generar salida CSV: pid, stack_id, asignaciones totales en bytes, recuento, histograma "stacktrace"
- `--flame <PATH>`: Generar flame graph

Ejemplo:

```bash
RUST_LOG=info cargo xtask run --release -- --program ~/dev/oss/coreutils/target/release/coreutils --order-by count --sample-every 100  --skip-count 100 --csv malocs.csv -f malloc --flame malocs.svg
```

Esto perfilará las llamadas a malloc en el programa ls, ordenará los resultados por recuento total de asignaciones, generará una salida CSV y creará un flame graph.

# Cómo funciona

El programa Ebpf se adjunta a la función malloc en el programa objetivo. Para cada n-ésima llamada, rastrea la traza de la pila y el tamaño de la asignación, y lo almacena en un hashmap local de la CPU.

El programa de espacio de usuario consulta estos mapas y resuelve las trazas de pila en símbolos. Al recibir la señal ctrl+c, agrega todos los datos y los imprime.

## Pendientes

- [x] Agregar el histograma en el espacio del kernel. Por ahora, solo volcamos todos los datos al espacio de usuario, lo que genera un overhead de 1us por llamada, lo cual es inaceptable. Un uprobe puro utiliza 20ns por llamada.
- [ ] Averiguar qué malloc se está utilizando (actualmente asumimos que el objetivo está enlazado estáticamente)
- [ ] Añadir una TUI basada en ratatui
- [x] Producir flamegraphs
- [x] Añadir documentación y ejemplos
- [ ] Demostrar de alguna manera al verificador de ebpf que el número [0,1] es un índice válido para la llamada a la función. Por ahora, da errores sorprendentes como:

```
Error: the BPF_PROG_LOAD syscall failed. Verifier output: 0: R1=ctx() R10=fp0
0: (bf) r6 = r1                       ; R1=ctx() R6_w=ctx()
1: (b7) r1 = 4                        ; R1_w=4
2: (63) *(u32 *)(r10 -280) = r1       ; R1_w=4 R10=fp0 fp-280=????4
3: (bf) r2 = r10                      ; R2_w=fp0 R10=fp0
4: (07) r2 += -280                    ; R2_w=fp-280
5: (18) r1 = 0xffff9f84a9a0dc00       ; R1_w=map_ptr(map=CONFIG,ks=4,vs=8)
7: (85) call bpf_map_lookup_elem#1    ; R0_w=map_value_or_null(id=1,map=CONFIG,ks=4,vs=8)
8: (15) if r0 == 0x0 goto pc+152      ; R0_w=map_value(map=CONFIG,ks=4,vs=8)
9: (79) r2 = *(u64 *)(r0 +0)          ; R0=map_value(map=CONFIG,ks=4,vs=8) R2=scalar()
10: (65) if r2 s> 0x2 goto pc+7       ; R2=scalar(smax=2)
11: (b7) r1 = 112                     ; R1_w=112
12: (15) if r2 == 0x0 goto pc+16      ; R2=scalar(smax=2,umin=1)
13: (15) if r2 == 0x1 goto pc+12      ; R2=scalar(smax=2,umin=2)
14: (15) if r2 == 0x2 goto pc+1 16: R0=map_value(map=CONFIG,ks=4,vs=8) R1=112 R2=2 R6=ctx() R10=fp0 fp-280=????mmmm
16: (b7) r1 = 96                      ; R1_w=96
17: (05) goto pc+11
29: (bf) r2 = r6                      ; R2_w=ctx() R6=ctx()
30: (0f) r2 += r1                     ; R1_w=96 R2_w=ctx(off=96)
31: (79) r8 = *(u64 *)(r2 +0)
dereference of modified ctx ptr R2 off=96 disallowed
verification time 73 usec
stack depth 280+0
processed 22 insns (limit 1000000) max_states_per_insn 0 total_states 2 peak_states 2 mark_read 2
```

## Licencia

Apache 2.0 o MIT

## Contribuciones

¡Las contribuciones son bienvenidas! Por favor, siéntase libre de enviar un Pull Request.
