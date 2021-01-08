<p align="center"><img src="README.assets/image-20210102025057323.png"></p>

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

- easier to **write**: never worry about minor formatting concerns while hacking away,
- easier to **read**: when all code looks the same you need not mentally convert others' formatting style into something you can understand.
- easier to **maintain**: mechanical changes to the source don't cause unrelated changes to the file's formatting; diffs show only the real changes.
- **uncontroversial**: never have a debate about spacing or brace position ever again!

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

## How to build your first web application with Go

> https://freshman.tech/web-development-with-go/

