---
layout: post
title:  "Introduction to static code analysis with Joern"
date:   2024-02-10 16:42:48 +0100
categories: code analysis
---

# 0x0 Intro

I took interest in static code analysis at work because it helped me uncover more vulnerabilities during web application audits. This article outlines my experience with code auditing over the past year.

I relied on Joern, a static code analysis tool which allows to scan for patterns into source code (even binaries and bytecode). Joern uses a graph representation (CPG) of the source code on which you can perform custom queries to find vulnerabilities.

In this article, I'll showcase the basics of Joern on the default Java Spring webapp. You can find all the information on how to set it up [here](https://spring.io/quickstart).

# 0x1 The target 

Here's the code provided in Spring's quickstart. By looking at the code, there's two obvious things:
- The endpoint GET /hello takes a parameter "name" which leds to a reflected XSS
- This endpoint does not require authentication, in this example it doesn't matter but in some cases it's critical

{% highlight java %}
package com.example.demo;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
@RestController
public class DemoApplication {
    public static void main(String[] args) {
      SpringApplication.run(DemoApplication.class, args);
    }

    @GetMapping("/hello")
    public String hello(@RequestParam(value = "name", defaultValue = "World") String name) {
      return String.format("Hello %s!", name);
    }
}
{% endhighlight %}

This example is trivial but we will use Joern to build scan queries that could be used in a much larger codebase.

# 0x2 Uncovering attack surface

All the analysis can be performed from Joern's interactive shell. The first step is to convert the source code  or the binary as a CPG in order to make queries. As the binary version of my application was available in my app's directory, Joern automatically selected jimple2cpg (Java bytecode to CPG). Java2src would be used otherwise.

{% highlight java %}
joern> importCode(inputPath = ".", projectName = "joern-demo-spring")
{% endhighlight %}

The next query searches for all the mapping annotations provided by the Spring framework (@GetMapping, @PostMapping, etc.), as they determine how endpoints are mapped for users. It's important to note that while these annotations provide valuable insight, they may not always reveal the full path from the properties of the annotation.

{% highlight java %}
joern> cpg.annotation.fullName("org\\.springframework\\.web\\.bind\\.annotation\\..*Mapping").l
{% endhighlight %}

Before continuing, let's break down the query. The **cpg** variable contains the whole graph that represents our source code. The nodes of this graph can be methods, calls, class declarations, etc. By accessing the property **annotation** of the cpg, we retreive all nodes that are annotations. Then we select annotations based on their type with the property **fullName**, which takes a regular expression as a parameter.

This approach yields the following results:

{% highlight java %}
val res2: List[io.shiftleft.codepropertygraph.generated.nodes.Annotation] = List(
  Annotation(
    id = 9503L,
    argumentIndex = -1,
    argumentName = None,
    code = "@GetMapping(value = {\"/hello\"})",
    columnNumber = None,
    fullName = "org.springframework.web.bind.annotation.GetMapping",
    lineNumber = Some(value = 16),
    name = "GetMapping",
    order = 6
  )
)
{% endhighlight %}

We can extend the query in order to get the methods associated with the previously selected annotations:

{% highlight java %}
joern> cpg.annotation.fullName("org\\.springframework\\.web\\.bind\\.annotation\\..*Mapping").method.l
val res9: List[io.shiftleft.codepropertygraph.generated.nodes.Method] = List(
  Method(
    id = 9472L,
    astParentFullName = "com.example.demo.DemoApplication",
    astParentType = "TYPE_DECL",
    columnNumber = None,
    columnNumberEnd = None,
    filename = "/tmp/jimple2cpg-10804044874919480453/com/example/demo/DemoApplication.class",
    fullName = "com.example.demo.DemoApplication.hello:java.lang.String(java.lang.String)",
    hash = None,
    isExternal = false,
    lineNumber = Some(value = 16),
    lineNumberEnd = Some(value = 12),
    name = "hello",
    offset = None,
    offsetEnd = None,
    order = 5,
    signature = "java.lang.String(java.lang.String)"
  )
)
{% endhighlight %}

Joern enables us to store these results as iterators using variables, which helps maintain query readability and manageability. Personally, I find using variables preferable to avoid cumbersome, unreadable queries.

{% highlight java %}
joern> def endpoint_method = cpg.annotation.fullName("org\\.springframework\\.web\\.bind\\.annotation\\..*Mapping").method
{% endhighlight %}

# 0x3 Detecting a vulnerable pattern

When searching for reflected XSS, we need to answer the question: Is the user controlled parameter reflected in the response page? Fortunately, Joern offers us the capability to establish relationships between elements in its graph, allowing us to determine if two elements are interconnected in the codebase.

In our scenario, our objective is to know if the return value of the method is controlled by the "name" variable. We'll have to identify two nodes and check if they are related:
- The parameter "name" of the method "hello"
- The return value of the method "hello"

{% highlight java %}
joern> def endpoint_params = endpoint_method.parameter.orderGt(0)
joern> def method_return = endpoint_method.methodReturn
{% endhighlight %}

The orderGt(0) trick is employed to exclude the 'this' variable from the parameter list of the 'hello' method. Retaining it could potentially introduce false positives when testing for reachability between nodes.

Now that we have the two key nodes, here comes the magic of Joern:

{% highlight java %}
joern> method_return.reachableByFlows(endpoint_params).p
val res8: List[String] = List(
  """_______________________________________________________________________________________________________________________________________________________
| nodeType          | tracked                        | lineNumber| method| file                                                                        |
|======================================================================================================================================================|
| MethodParameterIn | hello(this, java.lang.Strin... | 16        | hello | /tmp/jimple2cpg-15072187404306561014/com/example/demo/DemoApplication.class |
| Identifier        | $stack2[0] = name              | 17        | hello | /tmp/jimple2cpg-15072187404306561014/com/example/demo/DemoApplication.class |
| Call              | $stack2[0] = name              | 17        | hello | /tmp/jimple2cpg-15072187404306561014/com/example/demo/DemoApplication.class |
| Identifier        | format(\"Hello %s!\", $stack2)   | 17        | hello | /tmp/jimple2cpg-15072187404306561014/com/example/demo/DemoApplication.class |
| Call              | format(\"Hello %s!\", $stack2)   | 17        | hello | /tmp/jimple2cpg-15072187404306561014/com/example/demo/DemoApplication.class |
| Identifier        | $stack3 = format(\"Hello %s!... | 17        | hello | /tmp/jimple2cpg-15072187404306561014/com/example/demo/DemoApplication.class |
| Identifier        | return $stack3;                | 17        | hello | /tmp/jimple2cpg-15072187404306561014/com/example/demo/DemoApplication.class |
| Return            | return $stack3;                | 17        | hello | /tmp/jimple2cpg-15072187404306561014/com/example/demo/DemoApplication.class |
| MethodReturn      | RET                            | 16        | hello | /tmp/jimple2cpg-15072187404306561014/com/example/demo/DemoApplication.class |
"""
)
{% endhighlight %}

The ".p" at the end of the query prettifies the output. Here we can see the path between our two nodes, meaning that there is a potential vulnerability pattern.

# 0x4 Final thoughts

Here we are, we covered the basics of Joern in this article and you should be able to craft your own queries by now. The methodology outlined serves as a blueprint for addressing basic injections like SQLIs and beyond.

You can be even more creative by trying to find application logic issues in your applications. For example, I was able to find broken access control issues in production thanks to this wonderfull tool (I'll show how I did it in another post if anyone is interested). You can also chain Joern with other tools to enchance your application audits, I found a way to process Java Server Pages with Joern (I can cover that in the future too).

Thanks for reading.
