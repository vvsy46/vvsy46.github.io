---
title: "Largebin Attack"
date: 2026-09-08 19:29:00 +0900
categories: [Pwnable]
tags: [Pwnable, Exploit, CTF]
---

## 1. Largebin Attack이란?
- glibc `ptmalloc`에서 Largebin에 chunk를 삽입하는 과정에서 발생하는 포인터 갱신을 악용하여 원하는 주소에 heap chunk 주소를 작성하는 공격 기법
- 일반적으로 bin 연결을 위환 `fd`, `bk`뿐만 아니라, `fd_nextsize`, `bk_nextsize` 포인터가 존재
- Heap Overflow나 UAF등을 통해 이미 Largebin에 들어간 chunk의 metadata를 변조하고, 이후 `malloc()` 과정에서 allocator가 Largebin을 갱신할 때 의도한 주소에 값을 쓰게 하는 취약점

## 2. Largebin 관리 방식
- 서로 다른 크기의 chunk들을 관리해야 하기 때문에 `fd_nextsize`와 `bk_nextsize`를 이용해 chunk size를 기준으로 연결 구조를 유지한다.
```text
                fd_nextsize
                --------->
[ larger ]    [ medium ]    [ smaller ]
                <---------
                bk_nextsize
```
Large Bin Attack에서는 이 중 `fd_nextsize`와 `bk_nextsize`를 갱신하는 동작이 중요하다.

## 3. Largebin 구조체 
```c
struct malloc_chunk { 
    size_t prev_size; // 0x0
    size_t size;      // 0x8

    struct malloc_chunk *fd; // 0x10
    struct malloc_chunk *bk; // 0x18

    struct malloc_chunk *fd_nextsize; // 0x20
    struct malloc_chunk *bk_nextsize; // 0x28
};
```
여기서 중요한 점은 `fd_nextsize`가 chunk 시작 주소 기준 `+0x20`에 있다는 것이다.  
즉, glibc가 `chunk->fd_nextsize = B;`와 같은 코드를 실행하면,  
실제로는 `*(chunk + 0x20) = B;`의 write가 발생한다.  
따라서 원하는 주소 **TARGET에 B를 쓰고 싶다면** **chunk + 0x20 = TARGET**이 되도록 조절하면 된다.

## 4. Largebin Attack
> A: 기존에 largebin에 있던 chunk  
> B: 새로 largebin에 들어가는 chunk

공격자는 UAF나 overflow 등을 이용해 이미 largebin에 들어간 A의 `bk_nextsize`를 변조한다.  
`A->bk_nextsize = TARGET - 0x20;`

이후 `malloc()`을 호출해 B가 unsorted bin에서 largebin으로 이동하면서 정렬 삽입되도록 만든다.  
이 과정에서 glibc는 largebin의 nextsize 연결을 갱신한다.
```c
B->bk_nextsize = A->bk_nextsize;
B->bk_nextsize->fd_nextsize = B;
A->bk_nextsize = B;
``` 
즉, 공격자가 미리 `A->bk_nextsize = TARGET - 0x20;` 로 만들어두었다면,  
`B->bk_nextsize = A->bk_nextsize;`실행 후에는 `B->bk_nextsize = TARGET - 0x20;`가 된다.  
그 다음 glibc는 `B->bk_nextsize->fd_nextsize = B;`를 실행한다.  
대입하면 `(TARGET - 0x20)->fd_nextsize = B;`  
**fd_nextsize**는 chunk 기준 +0x20에 있으므로 `*((TARGET - 0x20) + 0x20) = B;`  
결과적으로 `*(TARGET) = B;`가 된다.

## 5. 요약
- A를 largebin에 넣음
- B를 unsorted bin에 둠
- A->bk_nextsize = target - 0x20 으로 변조
- malloc으로 B가 largebin에 삽입됨
- glibc가 target에 B 주소를 써줌