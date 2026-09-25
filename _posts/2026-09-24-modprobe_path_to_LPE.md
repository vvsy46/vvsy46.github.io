---
title: "[Kernel] modprobe_path overwrite to LPE"
date: 2026-09-24 00:00:00 +0900
categories: [Kernel, Pwnable]
tags: [linux, kernel, kaslr, vmemmap, modprobe_path]
---

커널 익스플로잇에서 자주 쓰이는 최종 목표 중 하나는 `modprobe_path` 전역 문자열을 덮어 **root 권한 실행(LPE)** 을 얻는 것이다.  

## 1. modprobe_path overwrite → LPE

`modprobe_path`는 커널이 커널 모듈을 자동 로드할 때 실행하는 usermode helper의 경로다.  
기본값은 `/sbin/modprobe`이고, 커널은 이 경로의 프로그램을 `call_usermodehelper()`로 **root 권한, 초기 네임스페이스**에서 실행한다.  
따라서 이 문자열을 공격자가 만든 스크립트 경로로 바꿔 두면, 커널이 대신 그 스크립트를 root로 실행해 준다.

커널이 modprobe를 호출하도록 유도하는 대표적인 방법은 **포맷을 알 수 없는 실행 파일**을 실행하는 것이다.

- 유저가 `execve()`로 파일을 실행하면 커널은 등록된 binfmt 핸들러들을 차례로 시도한다.
- 어떤 핸들러도 매직을 인식하지 못하면, 커널은 `request_module("binfmt-%04x", magic)`을 호출해 해당 포맷을 처리할 모듈을 로드하려 한다.
- 이 `request_module` → `call_modprobe()` → `call_usermodehelper()` 경로에서 우리가 덮어쓴 `modprobe_path`가 root로 실행된다.

즉 매직이 깨진 파일을 하나 실행하는 것만으로, 커널이 우리가 심어 둔 경로를 root로 불러 준다.

> binfnt 핸들러란  
ELF인지, 스크립트(#!)인지 확인 -> 파일 포맷을 확인하는 커널 내부 모듈

### 1-1. 전체 흐름

![modprobe_path LPE flow](/assets/img/linux_kernel_3/modprobe_path_lpe.svg){: width="720" .light .shadow }
_modprobe_path 덮어쓰기부터 root 스크립트 실행까지_

### 1-2. modprobe_path address

위 시나리오의 전제는 `modprobe_path`가 있는 주소에 쓸 수 있다는 것이다. 그러려면 두 가지가 필요하다.

1. `modprobe_path`의 **런타임 주소**를 알아야 한다. KASLR 때문에 정적 심볼 주소를 그대로 쓸 수 없다.
2. 사용 중인 write primitive의 성격(가상주소 쓰기냐, physical/`struct page` 단위 쓰기냐)에 맞게 그 주소를 **변환**할 수 있어야 한다.

여기서 `kernel_base`, `physical kernel base`, `page_offset_base`, `vmemmap_base` 모두 커널 메모리 주소와 관련 있지만 의미와 용도가 다르다.

![Virtual vs Physical](/assets/img/linux_kernel_3/virtual_vs_physical.svg){: width="820" .light .shadow }
_같은 변수라도 virtual·physical 주소는 다르다 — MMU가 변환하고, 두 KASLR은 독립_

## 2. Virtual KASLR

`vmlinux`의 심볼 주소는 정적 분석을 기준으로 정해져 있다.

```text
_text          = 0xffffffff81000000
commit_creds   = 0xffffffff810c9b40
modprobe_path  = 0xffffffff8293d240
```

하지만 KASLR이 활성화되면 실제 부팅 시 커널 image가 다른 virtual address에 배치된다.

```text
runtime symbol = static symbol + virtual KASLR slide
```

따라서 kernel text나 전역 변수, 함수 포인터를 사용하려면 먼저 virtual KASLR slide를 알아야 한다.  
일반적으로 커널 포인터를 leak한 뒤, 알고 있는 static symbol 주소를 빼서 구한다.

```text
virtual slide = leaked runtime address - static symbol address
```

![Virtual KASLR](/assets/img/linux_kernel_3/virtual_kaslr.svg){: width="720" .light .shadow }
_정적 심볼 주소에 slide를 더하면 런타임 주소가 된다_

이 slide만 알면 `modprobe_path`의 **가상주소**는 바로 계산된다.  
가상주소에 직접 쓰는 write primitive라면 여기서 끝이다.  
하지만 physical/`struct page` 단위로 쓰는 primitive라면 아래 개념들이 더 필요하다.

## 3. Physical KASLR

Virtual KASLR은 커널 image가 보이는 **가상주소**를 바꾼다.  
Physical KASLR은 kernel image가 RAM에 적재되는 **물리주소**를 바꾼다.

```text
kernel virtual base  = 0xffffffff81000000 + virtual slide
kernel physical base = 0x01000000         + physical slide
```

두 slide는 별개의 값이다.  
따라서 virtual KASLR을 leak했다고 해서 `modprobe_path`의 물리주소를 바로 알 수 있는 것은 아니다.

심볼의 kernel image 내부 offset은 KASLR과 무관하게 일정하다.

```text
modprobe_path offset
= 0xffffffff8293d240 - 0xffffffff81000000
= 0x193d240
```

따라서 `modprobe_path`의 물리주소는 다음과 같다.

```text
modprobe physical address
= kernel physical base + 0x193d240
= 0x01000000 + physical slide + 0x193d240
```

![Physical KASLR](/assets/img/linux_kernel_3/physical_kaslr.svg){: width="760" .light .shadow }
_물리주소는 physical slide로만 결정 — virtual slide와 독립_

## 4. Direct Map

커널은 RAM을 자신의 virtual address 공간에 연속적으로 매핑한다. 이를 direct map 또는 physmap이라고 부른다.

단순화하면 물리주소와 direct-map 주소의 관계는 다음과 같다.

```text
direct-map virtual address = page_offset_base + physical address
physical address = virtual address - page_offset_base
```

![Direct Map](/assets/img/linux_kernel_3/direct_map.svg){: width="720" .light .shadow }
_RAM을 page_offset_base부터 연속 매핑_

`page_offset_base` 역시 부팅할 때 randomize될 수 있다.  
따라서 임의의 물리주소를 알고 있어도 `page_offset_base`를 모르면 그 주소를 직접 kernel virtual address로 변환할 수 없다.

## 5. vmemmap

커널은 각각의 physical page를 관리하기 위해 `struct page`를 사용한다.  
모든 physical page에 대응하는 `struct page` 배열이 매핑된 영역이 `vmemmap`이다.

x86-64의 전형적인 구성에서 `sizeof(struct page)`는 `0x40`(64바이트), page 크기는 `0x1000`(4KB)이다.  
다만 `sizeof(struct page)`는 커널 버전과 config(예: `CONFIG_MEMCG`, `CONFIG_SLUB` 관련 필드 등)에 따라 달라질 수 있으므로, 아래 식에 대입하기 전에 대상 커널의 실제 값을 확인하는 것이 좋다.

![vmemmap](/assets/img/linux_kernel_3/vmemmap.svg){: width="760" .light .shadow }
_PFN으로 struct page ↔ physical page 대응_

```text
PFN = physical address / 0x1000
struct page address = vmemmap_base + PFN * sizeof(struct page)
```

반대로 `struct page *`에서 대응하는 physical address를 구하면 다음과 같다.

```text
PFN = (page - vmemmap_base) / sizeof(struct page)
physical address = PFN * 0x1000
```

해당 page가 direct map에서 보이는 주소는 다음과 같다.

```text
page_address(page)
= page_offset_base
  + ((page - vmemmap_base) / sizeof(struct page)) * 0x1000
```

`sizeof(struct page)`가 `0x40`인 경우 `0x1000 / 0x40 = 0x40`이므로 위 식은 다음처럼 정리된다.

```text
page_address(page)
= page_offset_base + (page - vmemmap_base) * 0x40
```

즉 `vmemmap_base`를 알면 원하는 physical address에 대응하는 `struct page *`를 만들 수 있다. `struct page` 단위 write primitive로 1절의 modprobe_path overwrite에 도달하려면 이 변환이 필요하다.

## 6. 커널 주소 변환을 이용한 vmemmap_base leak

`vmemmap_base`는 다음과 같은 방법으로 구할 수 있다.  
핵심 아이디어는 **공격자가 값을 정한 `struct page *`를 커널이 주소 변환하게 만들고, 그 변환 결과를 관찰**하는 것이다.
- 공격자가 임의의 `struct page *`(= `fake_page`)를 커널 경로에 흘려보낸다.
- 커널이 `page_address()`류의 변환을 수행하면서 그 주소를 사용/노출한다.
- 그 결과 주소를 leak한 뒤, 아래 관계식을 역으로 풀어 `vmemmap_base`를 복구한다.

```text
result address
= page_offset_base + (fake_page - vmemmap_base) * 0x40
```

`fake_page`는 공격자가 정한 값이고 `result address`는 leak으로 얻는다.  
여기에 direct map 정렬 조건과 가능한 주소 범위를 적용하면 `vmemmap_base`를 역산할 수 있다.

### 6-1. READ_FIXED: Oops fault address leak

구체적인 한 가지 예시는, 손상시킨 `pipe_buffer.page`에 `fake_page`를 넣고 커널이 그 page를 매핑하게 만들어 Oops를 유도하는 것이다.

```c
pipe_buffer.page   = fake_page;
pipe_buffer.offset = 0;
pipe_buffer.len    = 16;
```

손상된 pipe에 `io_uring READ_FIXED`를 수행하면 커널은 `fake_page`를 정상적인 `struct page *`라고 생각한다.

```text
io_read_fixed
  -> anon_pipe_read
  -> copy_page_to_iter
  -> kmap_local_page(fake_page)
  -> invalid source access
  -> Oops
```

이때 fault address가 `CR2` 또는 Oops register에 출력되며, 이 값이 위 식의 `result address`가 된다.  
`pipe_buffer` 외에도 `struct page *`를 다루는 다른 경로(예: 각종 page cache/DMA/graphics 관련 primitive)로도 같은 관계식을 만들 수 있다.

## 7. 4-level Paging과 5-level Paging

x86-64의 4-level paging과 5-level paging은 사용할 수 있는 virtual address 범위가 다르다.

```text
4-level paging: 48-bit virtual address
5-level paging: 57-bit virtual address
```

5-level paging에서는 kernel memory layout의 randomization 범위도 훨씬 넓어진다.  
따라서 4-level 환경에서 사용하던 좁은 `vmemmap_base` brute force 범위를 그대로 적용할 수 없다.

하지만 page 변환 관계 자체는 같다.

```text
struct page *
  -> PFN
  -> physical address
  -> direct-map address
```

## 8. 전체 Exploit Flow

앞의 개념들을 순서대로 엮으면, modprobe_path LPE는 대체로 다음 흐름으로 완성된다.

```text
virtual KASLR leak
  -> runtime kernel symbol address 계산

struct page* 변환 primitive
  -> 커널이 변환한 주소 leak
  -> vmemmap_base 복구

physical KASLR 처리
  -> modprobe_path 의 physical address 확인
  -> physical address 를 struct page* 로 변환
  -> page 단위 read/write primitive 로 modprobe_path overwrite

트리거
  -> 매직 깨진 파일 execve
  -> 커널이 modprobe_path(= 우리 스크립트)를 root 로 실행  ==> LPE
```

> 위 흐름의 leak/overwrite 단계에서 쓰이는 primitive는 대상마다 다르다. 6절의 pipe_buffer + `io_uring READ_FIXED`는 그중 한 가지 구현 예시일 뿐이다. 가상주소에 직접 쓰는 primitive라면 `page_offset_base`/`vmemmap_base` 단계는 건너뛰고 2절의 가상주소 계산만으로 충분하다.

정리하면 각 base의 역할은 다음과 같다.

| 값 | 의미 | 익스플로잇에서의 용도 |
|---|---|---|
| virtual KASLR slide | kernel image의 가상주소 이동량 | 함수와 전역 심볼의 runtime address 계산 |
| physical KASLR slide | kernel image의 물리주소 이동량 | `modprobe_path`의 physical address 계산 |
| `page_offset_base` | RAM direct map의 시작 주소 | physical address와 kernel virtual address 변환 |
| `vmemmap_base` | `struct page` 배열의 시작 주소 | physical page에 대응하는 `struct page *` 생성 |
