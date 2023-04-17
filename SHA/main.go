package main

import (
	"fmt"
)

// SHA 函数的结构体
type SHA1Context struct {
	Length_Low_70          uint32   // 消息长度低 32 位
	Length_High_70         uint32   // 消息长度高 32 位
	Message_Block_70       [64]byte // 512bits 的块，总共 64 个字节
	Message_Block_Index_70 int      // 512bits 块索引号
	Computed_70            int
	Corrupted_70           int
}

// 循环左移 bits 位
func SHA1CircularShift_70(bits uint32, word uint32) uint32 {
	return ((word << bits) & 0xFFFFFFFF) | (word >> (32 - bits))
}

// 赋初值函数
func SHA1Reset_70(context *SHA1Context) {
	context.Length_Low_70 = 0
	context.Length_High_70 = 0
	context.Message_Block_Index_70 = 0
	context.Computed_70 = 0
	context.Corrupted_70 = 0
}

// 每 512bits 数据块处理
func SHA1ProcessMessageBlock_70(context *SHA1Context) {
	var t uint32
	var W [80]uint32
	for t = 0; t < 16; t++ {
		W[t] = (uint32(context.Message_Block_70[t*4]) << 24) |
			(uint32(context.Message_Block_70[t*4+1]) << 16) |
			(uint32(context.Message_Block_70[t*4+2]) << 8) |
			(uint32(context.Message_Block_70[t*4+3]))
	}
	for t = 16; t < 80; t++ {
		W[t] = SHA1CircularShift_70(1, W[t-3]^W[t-8]^W[t-14]^W[t-16])
	}
	fmt.Printf("W[0] = %08x\n", W[0])
	fmt.Printf("W[1] = %08x\n", W[1])
	fmt.Printf("W[14] = %08x\n", W[14])
	fmt.Printf("W[15] = %08x\n", W[15])
	fmt.Printf("W[16] = %08x\n", W[16])
	fmt.Printf("W[79] = %08x\n", W[79])
	fmt.Printf("\n")
	// 每处理一块之后，SHAContext 块索引 0
	context.Message_Block_Index_70 = 0
}

// 填充函数
func SHA1PadMessage_70(context *SHA1Context) {
	if context.Message_Block_Index_70 > 55 {
		context.Message_Block_70[context.Message_Block_Index_70] = 0x80
		context.Message_Block_Index_70++
		for context.Message_Block_Index_70 < 64 {
			context.Message_Block_70[context.Message_Block_Index_70] = 0
			context.Message_Block_Index_70++
		}
		SHA1ProcessMessageBlock_70(context)
		for context.Message_Block_Index_70 < 56 {
			context.Message_Block_70[context.Message_Block_Index_70] = 0
			context.Message_Block_Index_70++
		}
	} else {
		context.Message_Block_70[context.Message_Block_Index_70] = 0x80
		context.Message_Block_Index_70++
		for context.Message_Block_Index_70 < 56 {
			context.Message_Block_70[context.Message_Block_Index_70] = 0
			context.Message_Block_Index_70++
		}
	}
	context.Message_Block_70[56] = byte((context.Length_High_70 >> 24) & 0xFF)
	context.Message_Block_70[57] = byte((context.Length_High_70 >> 16) & 0xFF)
	context.Message_Block_70[58] = byte((context.Length_High_70 >> 8) & 0xFF)
	context.Message_Block_70[59] = byte((context.Length_High_70) & 0xFF)
	context.Message_Block_70[60] = byte((context.Length_Low_70 >> 24) & 0xFF)
	context.Message_Block_70[61] = byte((context.Length_Low_70 >> 16) & 0xFF)
	context.Message_Block_70[62] = byte((context.Length_Low_70 >> 8) & 0xFF)
	context.Message_Block_70[63] = byte((context.Length_Low_70) & 0xFF)
	SHA1ProcessMessageBlock_70(context)
}

func SHA1Result_70(context *SHA1Context) int {
	if context.Corrupted_70 != 0 {
		return 0
	}
	if context.Computed_70 == 0 {
		SHA1PadMessage_70(context)
		context.Computed_70 = 1
	}
	return 1
}

func SHA1Input_70(context *SHA1Context, message_array []byte, length uint) {
	if length == 0 {
		return
	}
	if context.Computed_70 != 0 || context.Corrupted_70 != 0 {
		context.Corrupted_70 = 1
		return
	}
	for _, b := range message_array {
		context.Message_Block_70[context.Message_Block_Index_70] = b & 0xFF
		context.Message_Block_Index_70++
		context.Length_Low_70 += 8
		context.Length_Low_70 &= 0xFFFFFFFF
		if context.Length_Low_70 == 0 {
			context.Length_High_70++
			context.Length_High_70 &= 0xFFFFFFFF
			if context.Length_High_70 == 0 {
				context.Corrupted_70 = 1
			}
		}
		if context.Message_Block_Index_70 == 64 {
			SHA1ProcessMessageBlock_70(context)
		}
	}
}

func main() {
	var sha SHA1Context
	var input string
	fmt.Printf("Please input word: ")
	fmt.Scanln(&input)
	fmt.Printf("SHA1:%s", input)
	fmt.Printf("\n")
	SHA1Reset_70(&sha)
	SHA1Input_70(&sha, []byte(input), uint(len(input)))
	SHA1Result_70(&sha)
}
