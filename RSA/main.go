package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// 平方乘方法a^n mod n
func LRFun_70(a, n int64, key []int, klen int, flag bool) int64 {
	s := int64(1)
	for i := klen - 1; i >= 0; i-- {
		s = (s * s) % n
		if key[i] == 1 {
			s = (s * a) % n
		}
		if flag {
			fmt.Printf("i=%d, %d\n", i, s)
		}

	}
	return s
}

// 模重复平方法
func RLFun_70(a, n int64, key []int, klen int, flag bool) int64 {
	s := int64(1)
	for i := 0; i < klen; i++ {
		if key[i] == 1 {
			s = (s * a) % n
		}
		a = (a * a) % n
		if flag {
			fmt.Printf("i=%d, %d\n", i, s)
		}
	}
	return s
}

// 扩展欧几里得
func Exgcd_70(a, b int64, x, y *int64) int64 {
	if b == 0 {
		*x = 1
		*y = 0
		return a
	}
	r := Exgcd_70(b, a%b, x, y)
	temp := *x
	*x = *y
	*y = temp - a/b**y
	return r
}

// 求a的逆元x
func mod_reverse_70(a, n int64) int64 {
	var x, y int64
	r := Exgcd_70(a, n, &x, &y)
	if r == 1 {
		return (x%n + n) % n
	}
	return -1
}

// 将整数转换为二进制切片
func intToBin_70(n int64) []int {
	binary := make([]int, 0)
	for n > 0 {
		binary = append(binary, int(n%2))
		n /= 2
	}
	return binary
}

// 计算二进制切片的长度
func bitCount_70(n int64) int {
	count := 0
	for n > 0 {
		count++
		n /= 2
	}
	return count
}

// 清空输入缓冲区
func clearInput() {
	reader := bufio.NewReader(os.Stdin)
	_, _ = reader.ReadBytes('\n')
}

// 判断输入是否为数字，并对字符串进行ascii码处理
func isDigit_70(input string, output string) (int64, bool) {
	var bool2 bool
	//判断明文是否为数字，并进行转化
	if _, err := strconv.Atoi(input); err == nil {
		// 如果输入是数字字符串，直接保持不变
		output = input
	} else {
		// 如果输入是字符串，将每个字符转换为对应的ASCII码并拼接成新数字
		fmt.Print("输入为字符串，将其每位转化为acsii码:")
		for _, c := range input {
			output += strconv.Itoa(int(c))
		}
		fmt.Print(output + "\n")
		bool2 = true
	}

	//赋值
	m, err := strconv.ParseInt(output, 10, 64)
	if err != nil {
		fmt.Println("error")
		return 0, false
	}
	return m, bool2
}

// 明文判断是否大于模数，用模运算进行处理
func isBig_70(m int64, n int64) *[2]int64 {
	//变量余数	商
	var m1 [2]int64
	if m > n {
		m1[0] = m % n
		m1[1] = m / n
	}
	return &m1
}

// 当明文大于模数时，进行分组加密
func group(m int64, e int64, n int64, p int64, q int64) int64 {

	var m1 [2]int64
	var s, sign int64
	var de int64
	sign = 1
	de = 0
	decrypted_m := make(map[int]int64)
	de = m
	var i = 1

	for sign == 1 {
		fmt.Printf("RSA第%d组 底数 指数 模数为：%d %d %d\n", i, m, e, n)
		phi_n := (p - 1) * (q - 1)
		d := mod_reverse_70(e, phi_n)
		// 使用公钥加密
		fmt.Println("平方乘")
		LRFun_70(m, n, intToBin_70(e), bitCount_70(e), true)

		c := RLFun_70(m, n, intToBin_70(e), bitCount_70(e), false)
		fmt.Printf("加密后的密文为: %d\n", c)

		// 使用私钥解密
		fmt.Printf("RSA解密模幂运算底数 指数 模数为：%d %d %d\n", c, d, n)
		fmt.Println("模重复平方")
		decrypted_m[i] = RLFun_70(c, n, intToBin_70(d), bitCount_70(d), true)
		LRFun_70(c, n, intToBin_70(d), bitCount_70(d), false)
		fmt.Printf("解密后的明文为: %d\n", decrypted_m[i])
		//将商当作明文准备下一轮加密
		m = s
		m1 = *isBig_70(m, n)
		if m1[0] > 0 {
			m = m1[0]
			s = m1[1]
			sign = 1
		} else {
			sign = 0
		}
		i++
	}
	//计算分组加密密文
	for j := 1; j < i; j++ {
		de = de + decrypted_m[j]*s
	}
	return de
}

func main() {
	// 测试数据
	var e, p, q, m, s, m2 int64
	var m1 [2]int64
	var sign int64
	var input, output string
	var bool1 bool

	fmt.Print("请顺序输入公钥，两素数：e p q:")
	fmt.Scanf("%d %d %d", &e, &p, &q)

	//清空缓冲区
	clearInput()

	// 计算 n 和 φ(n)
	n := p * q
	phi_n := (p - 1) * (q - 1)
	fmt.Printf("输出模数n：%d\n", n)
	fmt.Printf("输出模数n的欧拉函数 φ(n)：%d\n", phi_n)

	// 计算私钥 d
	d := mod_reverse_70(e, phi_n)
	fmt.Printf("输出模数私钥d：%d\n", d)

	// 明文
	fmt.Print("请输入需要加密的明文m：")
	fmt.Scanln(&input)

	//输入明文类型判断
	m, bool1 = isDigit_70(input, output)
	fmt.Printf("RSA加密模幂运算底数 指数 模数为：%d %d %d\n", m, e, n)

	//判断明文是否大于模数
	m1 = *isBig_70(m, n)
	if m1[0] > 0 {
		m = m1[0]
		s = m1[1]
		sign = 1
	} else {
		sign = 0
	}

	fmt.Printf("RSA第0组 底数 指数 模数为：%d %d %d\n", m, e, n)

	// 使用公钥加密
	fmt.Println("平方乘")
	LRFun_70(m, n, intToBin_70(e), bitCount_70(e), true)

	c := RLFun_70(m, n, intToBin_70(e), bitCount_70(e), false)
	fmt.Printf("加密后的密文为: %d\n", c)

	// 使用私钥解密
	fmt.Printf("RSA解密模幂运算底数 指数 模数为：%d %d %d\n", c, d, n)
	fmt.Println("模重复平方")
	decrypted_m := RLFun_70(c, n, intToBin_70(d), bitCount_70(d), true)
	LRFun_70(c, n, intToBin_70(d), bitCount_70(d), false)
	fmt.Printf("解密后的明文为: %d\n", decrypted_m)
	//判断是否需要分组
	if sign == 1 {
		//分组
		fmt.Println("")
		m2 = group(s, e, n, p, q)
		decrypted_m = decrypted_m + m2*n
		fmt.Printf("结合分组得明文为：%d\n", decrypted_m)
	} else {
		fmt.Println("")
	}
	//判断是否需要将明文转化为字符串
	if bool1 {
		var chars []string
		var m int = int(decrypted_m)
		s := strconv.Itoa(m)
		for i := 0; i < len(s); i += 2 {
			c := rune((s[i]-'0')*10 + (s[i+1] - '0'))
			chars = append(chars, string(c))
		}
		fmt.Print("转化为字符串为：")
		fmt.Println(strings.Join(chars, ""))
	}
}
