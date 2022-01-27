<p align="center"><img src="README.assets/golang.png"></p>

<br/>

## Contents

```bash
$ tree -L 2
.
├── 00_WebServer
│   └── main.go
├── 01_TryGo
│   └── main.go
├── 02_Packages
│   ├── README.md
│   ├── fiboMain.go
│   ├── fibonacci
│   └── randomNumber
├── 03_TypeDeduction
│   └── main.go
├── 04_BasicFunction
│   ├── factorial
│   └── hanoi
├── 05_String
│   ├── 1_hangul
│   ├── 2_HasConsonantSuffix
│   ├── 3_Example_printBytes_test.go
│   ├── 4_Modify_printBytes_test.go
│   └── 5_concatenate_test.go
├── 06_Array+Slice
│   ├── 1_Example_array_test.go
│   ├── 2_Example_slicing_test.go
│   ├── 3_Appending_to_a_slice_test.go
│   ├── 4_slice_capacity_test.go
│   ├── 5_slice_duplication_test.go
│   ├── 6_slice_insert_test.go
│   └── 7_stack_test.go
├── 07_Map
│   ├── 1_character_count.go
│   ├── 2_map_equality.go
│   ├── 3_maps_test.go
│   └── 4_set_test.go
├── 08_Input+Output
│   └── 1_io_test.go
├── LICENSE
├── README.assets
│   └── golang.png
└── README.md

17 directories, 23 files
```

### Practice

- Getting into Go

<br/>

<br/>

## Documentation

Go is a statically typed, compiled programming language designed at Google.

The Go programming language is an open source project to make programmers more productive.

Go is expressive, concise, clean, and efficient.

Its concurrency mechanisms make it easy to write programs that get the most out of multicore and networked machines, while its novel type system enables flexible and modular program construction.

Go compiles quickly to machine code yet has the convenience of garbage collection and the power of run-time reflection.

It's a fast, statically typed, compiled language that feels like a dynamically typed, interpreted language.

<br/>

<br/>

## gofmt

#### Introduction

[Gofmt](https://golang.org/cmd/gofmt/) is a tool that automatically formats Go source code.

Gofmt'd code is:

-   easier to **write**: never worry about minor formatting concerns while hacking away,
-   easier to **read**: when all code looks the same you need not mentally convert others' formatting style into something you can understand.
-   easier to **maintain**: mechanical changes to the source don't cause unrelated changes to the file's formatting; diffs show only the real changes.
-   **uncontroversial**: never have a debate about spacing or brace position ever again!

<br/>

#### Format your code

We recently conducted a survey of Go packages in the wild and found that about 70% of them are formatted according to gofmt's rules.

This was more than expected - and thanks to everyone who uses gofmt - but it would be great to close the gap.

To format your code, you can use the gofmt tool directly:

```
gofmt -w yourcode.go
```

Or you can use the "[go fmt](https://golang.org/cmd/go/#hdr-Gofmt__reformat__package_sources)" command:

```
go fmt path/to/your/package
```

<br/>

<br/>

## Compile and run Go program

```
go run [build flags] [-exec xprog] package [arguments...]
```

Run compiles and runs the named main Go package.

Command `go run` performs project's building under the hood and with flag _--work_ (`go run --work main.go`) you can see the location of temporary build files.

<br/>

<br/>

## Testing

Files containing tests should be called `name_test`, with the `_test` suffix. They should be alongside the code that they are testing.

To run the tests recursively call `go test -v ./...`

<br/>

<br/>

## How to build your first web application with Go

> https://freshman.tech/web-development-with-go/
