---
title: "[Kernel] modprobe_path overwrite to LPE"
date: 2026-09-24 00:00:00 +0900
categories: [Kernel, Pwnable]
tags: [linux, kernel, kaslr, vmemmap, modprobe_path]
---

최종 `modprobe_path`를 덮어 **root**를 얻는 것이다.  

## 1. overwrite modprobe_path -> root

`modprobe_path`는 커널이 모듈을 자동 로드할 때 실행하는 usermode helper의 경로 문자열이다.  
기본값은 `/sbin/modprobe`이고, 커널은 이 경로의 프로그램을 `call_usermodehelper()`로 **root 권한**으로 실행한다.  
따라서 이 문자열을 공격자 스크립트 경로로 바꿔 두면, 커널이 대신 그 스크립트를 root로 실행해 준다.

커널이 modprobe를 호출하게 만드는 대표적인 방법은 **포맷을 알 수 없는 실행 파일**을 실행하는 것이다.

- `execve()`로 파일을 실행하면 커널은 등록된 binfmt 핸들러들을 차례로 시도한다.
- 아무도 매직을 인식 못 하면 `request_module("binfmt-%04x", magic)`을 호출해 모듈을 로드하려 한다.
- 이 `request_module` → `call_modprobe()` → `call_usermodehelper()` 경로에서 우리가 덮어쓴 `modprobe_path`가 root로 실행된다.

즉 매직이 깨진 파일 하나만 실행하면, 커널이 우리가 심어 둔 경로를 root로 불러 준다.

![modprobe_path LPE flow](/assets/img/linux_kernel_3/modprobe_path_lpe.svg) <!--{: width="720" .shadow }-->

이를 위해 두 가지 조건이 필요하다.

1. `modprobe_path`가 **어디 있는지(주소)** 알아야 한다.
2. 내가 가진 **write 수단(primitive)** 으로 그 위치에 **도달**할 수 있어야 한다.

이 두 가지를 이해하려면 커널이 메모리를 어떻게 바라보는지 알아야 한다.

## 2. page & PFN
메모리를 바이트 하나하나 관리하면 너무 잘아서, 커널은 물리 메모리(RAM)를 **page(보통 4KB = `0x1000`)** 단위로 관리한다.  
그리고 물리 메모리의 각 page에 **0, 1, 2, … 순서대로 붙인 번호가 PFN(Page Frame Number)** 이다.   
즉 PFN은 "이 page가 물리 메모리의 몇 번째 조각인가"이다.

![page and PFN](/assets/img/linux_kernel_3/page_pfn.svg)<!-- {: width="760" .shadow }-->

## 3. 가상주소 vs 물리주소

CPU와 커널이 코드에서 쓰는 주소는 전부 **가상주소(virtual address)** 다.  
이걸 하드웨어(MMU)가 페이지 테이블을 보고 실제 RAM 위치인 **물리주소(physical address)** 로 번역해서 접근한다.

![Virtual vs Physical](/assets/img/linux_kernel_3/virtual_vs_physical.svg) <!--{: width="820" .shadow } -->  
커널이 같은 RAM을 여러 방식으로 매핑하기 때문에 같은 물리 바이트가 여러 개의 가상주소로 보일 수 있다.

## 4. KASLR
정적 분석에서 본 심볼 주소를 그대로 쓸 수 없는 이유가 KASLR이다.  
커널 이미지의 배치가 부팅마다 랜덤화되는데, **가상 배치와 물리 배치가 따로** 랜덤화된다.

### 4-1. Virtual KASLR
`vmlinux` 심볼 주소는 정적으로 고정돼 있다.

```text
_text          = 0xffffffff81000000
commit_creds   = 0xffffffff810c9b40
modprobe_path  = 0xffffffff8293d240
```

부팅 시 커널 이미지가 다른 가상주소에 올라가므로, 실제 주소는 slide 만큼 밀린다.

```text
runtime symbol = static symbol + virtual KASLR slide
virtual slide  = leaked runtime address - static symbol address
```

![Virtual KASLR](/assets/img/linux_kernel_3/virtual_kaslr.svg)  
이 slide만 알면 `modprobe_path`의 **가상주소**가 나온다.

### 4-2. Physical KASLR
Virtual KASLR은 커널 이미지가 보이는 **가상주소**를, Physical KASLR은 RAM에 적재되는 **물리주소**를 바꾼다.  
**두 slide는 서로 독립**이다.

```text
kernel virtual base  = 0xffffffff81000000 + virtual slide
kernel physical base = 0x01000000         + physical slide
```

이미지 내부 offset은 KASLR과 무관하게 일정하므로, 물리주소는 물리 배치로만 정해진다.

```text
modprobe_path offset  = 0xffffffff8293d240 - 0xffffffff81000000 = 0x193d240
modprobe 물리주소 P    = kernel physical base + 0x193d240
                     = 0x01000000 + physical slide + 0x193d240
```

![Physical KASLR](/assets/img/linux_kernel_3/physical_kaslr.svg)

## 5. Write Primitive
취약점에서 얻은 **write primitive의 성격**에 따라 modprobe_path에 도달하는 법이 달라진다.

- **(A) 임의 가상주소에 쓸 수 있는 경우** (예: ROP로 `memcpy` 호출)  
  → `modprobe_path`의 **가상주소**만 있으면 끝.
- **(B) 물리 메모리 / `struct page` 단위로만 쓸 수 있는 경우** (예: 조작된 `struct page *`, DMA, page 단위 R/W)  
  → 목표의 **물리주소 P**를 구한 뒤, 그 물리 page를 실제로 건드릴 **가상 좌표**로 변환해야 한다.

**(B)를 위해 필요한 두 도구가 바로 direct map과 vmemmap이다.**

## 6. Direct Map
**문제:** 커널도 결국 가상주소로만 메모리에 접근한다.  
물리주소 P에 있는 바이트를 쓰고 싶다면, **P를 가리키는 가상주소**가 필요하다.

**해결:** 커널은 부팅 때 **RAM 전체를 자기 가상 공간에 순서 그대로 1:1로 매핑**해 둔다.  
이 거울 영역이 direct map(physmap)이고, 시작 주소가 `page_offset_base`다.

![Direct Map](/assets/img/linux_kernel_3/direct_map.svg)

```text
direct-map 가상주소 = page_offset_base + 물리주소
```

`page_offset_base`도 부팅 때 randomize되므로, 물리주소 P를 알아도 이 base를 모르면 접근용 가상주소를 못 만든다.

## 7. vmemmap 과 struct page
**문제:** 커널은 각 물리 page의 상태(참조 수, 플래그 등)를 관리해야 하므로, **page 하나마다 `struct page`라는 메타데이터 구조체**를 둔다.  
그리고 수많은 커널 API가 물리주소가 아니라 **`struct page *`** 로 page를 주고받는다.  
-> 그래서 primitive가 이 계열이면 목표 page의 `struct page *`가 필요하다.

**해결:** 모든 물리 page의 `struct page`를 **PFN 순서대로 모아 둔 배열**이 vmemmap이고, 시작이 `vmemmap_base`다.  
`struct page` 하나 크기는 보통 `0x40`(64B).

![vmemmap](/assets/img/linux_kernel_3/vmemmap.svg){: width="760" .shadow }
_PFN 으로 struct page ↔ physical page 가 1:1 대응_

```text
struct page 주소 = vmemmap_base + PFN × 0x40      (PFN = 물리주소 / 0x1000)
그 page 의 실제 데이터 주소:  page_address = page_offset_base + PFN × 0x1000
```
즉 `vmemmap_base`를 알면 임의 물리 page의 `struct page *`를 만들 수 있고, 반대로 `struct page *`에서 물리주소·direct-map 주소로 되돌릴 수 있다.

## 8. 정리

#### 구체적 예시 (slide 값은 가정)
> - `virtual slide = 0x1e00000`  
- `physical slide = 0x3400000`  
- `page_offset_base = 0xffff888000000000`  
- `vmemmap_base = 0xffffea0000000000`  

```text
① 이미지 VA   = 0xffffffff8293d240 + 0x1e00000        = 0xffffffff8473d240
물리주소 P    = 0x01000000 + 0x3400000 + 0x193d240     = 0x05d3d240
PFN          = 0x05d3d240 / 0x1000                    = 0x5d3d
② direct-map = 0xffff888000000000 + 0x05d3d240        = 0xffff888005d3d240
③ struct page= 0xffffea0000000000 + 0x5d3d × 0x40     = 0xffffea0000174f40
```

- **①·②** 는 **같은 바이트(`"/sbin/modprobe"`)** 를 가리키는 서로 다른 가상주소. 어느 쪽에 써도 같은 변수가 바뀐다.
- **③** 은 그 page를 *설명하는* 구조체 주소라 **내용이 다르다**(문자열이 아님). 대신 ③에서 산술로 ②를 유도해 실제 바이트에 도달한다.

**(A) 가상주소 write면 ①만, (B) 물리/struct page write면 P→②/③로 변환.**

![kernel memory overview](/assets/img/linux_kernel_3/kernel_memory_overview.svg)  
`modprobe_path`는 RAM의 바이트 한 덩어리지만, 커널이 같은 물리 메모리를 여러 방식으로 매핑해 두기 때문에 **가상 공간에서 동시에 여러 주소로 보인다.**

| 좌표 | 어디서 | 무엇 |
|---|---|---|---|
| ① 이미지 VA | kernel image 매핑 | modprobe_path 심볼의 가상주소 |
| ② direct-map VA | direct map 거울 | 같은 물리 page의 또 다른 가상주소 |
| ③ struct page* | vmemmap 배열 | 그 page를 *설명하는* 메타데이터 주소 |

## 9. vmemmap_base 구하기 (leak)

(B) 경로를 쓰려면 `vmemmap_base`를 알아야 한다. 핵심 아이디어는 **공격자가 값을 정한 `struct page *`를 커널이 주소 변환하게 만들고, 그 결과를 관찰**하는 것이다.

```text
result address = page_offset_base + (fake_page - vmemmap_base) × 0x40
```

`fake_page`는 공격자가 정하고 `result address`는 leak으로 얻으므로, direct map 정렬 조건과 주소 범위를 적용해 `vmemmap_base`를 역산한다.  
vmemmap 전체를 blind brute force하는 것과 달리, 커널이 실제로 한 변환 결과를 역으로 푸는 방식이다.

### 9-1. 예시 — io_uring READ_FIXED 로 Oops fault address leak

손상시킨 `pipe_buffer.page`에 `fake_page`를 넣고 커널이 그 page를 매핑하게 만들어 Oops를 유도한다.

```c
pipe_buffer.page   = fake_page;
pipe_buffer.offset = 0;
pipe_buffer.len    = 16;
```

```text
io_read_fixed 
  -> anon_pipe_read 
  -> copy_page_to_iter 
  -> kmap_local_page(fake_page) 
  -> invalid access 
  -> Oops
```

이때 `CR2`/Oops 레지스터에 찍히는 fault address가 위 식의 `result address`가 된다.  
`pipe_buffer` 외에 `struct page *`를 다루는 다른 경로로도 같은 관계식을 만들 수 있다.

## 10. 4-level vs 5-level Paging

x86-64의 paging 레벨에 따라 가상주소 폭이 다르다.

```text
4-level: 48-bit virtual address
5-level: 57-bit virtual address
```

5-level에서는 kernel memory layout randomization 범위도 넓어져, 4-level용 좁은 `vmemmap_base` brute force 범위를 그대로 쓸 수 없다.  
다만 `struct page → PFN → 물리주소 → direct-map` 변환 관계 자체는 동일하다.

## 11. 전체 Exploit Flow

```text
[주소 구하기]
virtual KASLR leak     -> modprobe_path 의 가상주소(①) 계산

(A) 가상주소 write primitive 이면 여기서 바로:
    modprobe_path(①) 에 "/tmp/x" 쓰기  ---------------------┐
                                                            │
(B) 물리/struct page primitive 이면:                          │
    vmemmap_base leak  -> struct page* 변환 가능             │
    physical KASLR     -> modprobe_path 물리주소 P           │
    P -> struct page*(③) / direct-map VA(②) 로 변환          │
    ②/③ 를 통해 "/tmp/x" 쓰기  ------------------------------┤
                                                            ▼
[트리거]  매직 깨진 파일 execve -> 커널이 modprobe_path(=/tmp/x)를 root 로 실행  ==> LPE
```

정리하면 각 base의 역할은 다음과 같다.

| 값 | 의미 | 쓰임 |
|---|---|---|
| virtual KASLR slide | 이미지의 가상주소 이동량 | 심볼의 런타임 가상주소(①) 계산 |
| physical KASLR slide | 이미지의 물리주소 이동량 | modprobe_path 물리주소 P 계산 |
| `page_offset_base` | direct map(RAM 거울) 시작 | 물리주소 ↔ 가상주소(②) 변환 |
| `vmemmap_base` | struct page 배열 시작 | 물리 page ↔ struct page*(③) 변환 |
