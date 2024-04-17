---
layout: post
title:  "Static code analysis II: Investigating SQL injections with Joern"
date:   2024-04-05 16:42:48 +0100
categories: code analysis
---

# 0x0 Intro

In my previous article on static analysis, I demonstrated a basic use case of the Joern framework. While it showcased the functionalities of the framework, it didn't delve into the assumptions a security researcher would need to make in a real-world scenario in order to tell if a vulnerability is present or not in a codebase. Displaying the tool's capabilities on a small code snippet didn't provide insight into the motivations for using such a tool and the associated tradeoffs.

This article draws heavily from the methodology my team and I employed when investigating an SQL injection discovered during one of our bug bounty programs. Due to the application's codebase size, the analysis was quite challenging.

# 0x1 Quick reminder on SQL injections

Here's the piece of code we'll be looking at, it is taken from [this repo](https://github.com/malikashish8/vuln-spring) and it has been slightly modified:

{% highlight java linenos %}
@PostMapping("/login")
public HttpEntity<String> login(
		HttpSession session,
		@RequestParam(name = "username", required = true) String username,
		@RequestParam(name = "password", required = true) String password
	) {
	
    logger.debug("Login with: " + username + ":" + password);
		
	String logged_user = loginSuccess(username, password);
	if (logged_user != null) {
		session.setAttribute("username", username);
		return new HttpEntity<>("logged in \\o/, welcome " + logged_user + " !\n");
	}
	logger.debug("Failed login for " + username);
	return new HttpEntity<>("failed :c\n");
}

private String loginSuccess(String username, String password) {
	if (username == null || password == null)
		return null;
	try {
	    String query = "SELECT * FROM users" +
		    " WHERE USERNAME=\"" + username +
            "\" AND PASSWORD=\"" + password + "\"";
			
	logger.debug(query);
			
	Map<String, Object> result = jdbcTemplate.queryForMap(query);
	return result.get("username").toString();

	} catch (EmptyResultDataAccessException e) {
		return null;
	}
}
{% endhighlight %}

For those how are not familiar with spring framework, the code above creates and HTTP endpoint which accepts POST requests for the path /login. It takes mandatory parameters "username" and "password" in order to log in.

The line 23 should catch your intention as it's the most trivial case of SQL injection, the SQL query is created from strings directly controlled by the user of the application. Indeed, the parameters of login() (line 2) are both passed to loginSuccess() (line 19), which contains the vulnerable code.

The exploitation of this vulnerability is straightforward and I won't go in the basics of SQL injection methodology as it's covered in plenty of other ressources online. 

For sake of simplicity, let's suppose that an user named "bob" is already registered in the database but we don't know his password. The current implementation allows us to bypass the authentication as follows, with a simple curl request:

{% highlight bash %}
$ curl -XPOST --form-string 'username=bob";#' -F 'password=somerandompass' http://localhost:8082/login
logged in \o/, welcome bob !
{% endhighlight %}

The server will create the SQL request below from those parameters;

{% highlight java %}
SELECT * FROM users WHERE USERNAME="bob";#" AND PASSWORD="somerandompass"
{% endhighlight %}

Which is interpreted as:
{% highlight java %}
SELECT * FROM users WHERE USERNAME="bob";#
{% endhighlight %}

Done! We have exploited the SQLi! Easy right? Why bothering with complicated tools like Joern? Unfortunately, it was the simplest case possible an it holds in less than 30 lines of code, real life applications may contain thousands of lines. Reviewing SQLIs manually is the last thing you would ever want to do, especially when you have a lot of web services to test.

Some people would argue that dynamic scanning is far supperior because you don't rely on heavy parsing algorithms and code analysis frameworks in order to find vulnerabilities. In my experience, dynamic testing tool are not able to provide a sufficient coverage, even with all the work that is made to create sophisticated crawling tooling. The different commercial solutions I tested were not able to find the SQLi that the hunter reported us, and it was not a complicated case to exploit.

I suppose that the main reason for the lack of relevant results is that the dynamic scanner has no way to guess that there's and enpoint POST /login that takes 2 parameters with a specific name, unless if it relies on the source code or some description of the application (or crawling if you have a frontend). Also, a lot of heuristics are mediorce at best and you would spend more time triaging the false positives of your scanner. 

A these reasons led me to try out static code analysis. However, keep in mind that commercial or open source code scanners may suffer from different issues as they might not fit your application stack. And sometimes, even if they do, it does not work either. That's what appened with the Sonarqube Community that is set up at my work, it was capable of spotting trivial SQLIs but not the complex ones. I didn't spend too much time investigating what appened with Sonar as I prefer using Joern for investigating vulnerabilities quickly and deploy custom code analysis rules.

# 0x2 Hypothesis for automated detection

Before trying anything with Joern, we need to find out what kind of pattern in the code in enough to tell if there is a vulnerability or not. It means that our pattern must be sufficiently robust get the highest rate of true positives while keeping a relatively low rate of false positives. As every detection method, you will obviously have some false positives and you will miss some vulnerabilities.

If we recaptitulate the key elements we've seen while exploiting our SQLI:

- User controlled parameters

Some parameters were directly available to the user. Here, we recognise them with the annotation "RequestParam" and the annotation of the method login() "PostMapping". It is interesting to know where user input comes from as it provides a greater certainty on the likelyhood of exploitation. However, you would have to handle the cases where the parameters have different annotations than "RequestParam" and the sames goes for the method annotations. Indeed, the annotations could be something like "Override" if it implements a methods from an abstract controller. This pattern is not reliable as the abstract controller's code might be generated from API definition in some cases. Even worse, your java webapp is not necessarly built on top of Spring framework!

Another downside of this approach is that this pattern will miss second order SQL injections because they are not directly controlled by the user. For example, the payload might come from a database that has been modified by the user in previous exploitation step, with a proper SQL query for example.

For all theses reasons, I've choosen to ignore such patterns for now as it is a tedious task to list all the possible cases and I would miss a lot of vulnerabilities.

- String operations

We also noticed that our query is built from string concatenation. The string concatenation itself is not sufficient to prove that a vulnerability exists. However, it is a good indicator that the code has some issues if it is related to the SQL statement. Note that in real-life cases, they are multiple ways to modify a string. The most common I've seen are String.replace(..., ...) or StringBuilders. By having a few string operation signature, you can already create some robust rules.

- SQL libraries

This string query is passed as a parameter to jdbcTemplate.queryForMap(...) method as first argument, and the payload is triggered here. Like the other pieces of code, there is a lot of functions available in order to execute an SQL query. It is worth to spend a bit of your time preparing a list of those methods in order to get as much results as possible.


- Input filtering

Input filtering is something that we will ignore because there is so many ways to filter user input. It would take a lot of time to create proper signatures for all theses patterns and it would have little to no effects to search for such patterns at large scale. Ignoring bad implementation because of input filtering is a poor choice anyway.

To conclude on our choices regarding vulnerability pattern, we'll look for arguments of SQL library method that are SQL statement and that were manipulated by various string operations. There are other considerations that will be added in the next sections of this article.

# 0x3 Investigating with Joern - internal code reprentation 

Before using Joern to query vulnerable code patterns, let me give you a few words on Joern's internal code representation. My last article presented this data structure without providing any details and the queries worked like some kind of black magic. The code property graph (CPG) is a graph which contains several code representation combined:

- Abstract Syntax Tree (AST)

Roughly, the AST is a tree structure of the source code based on the languages syntax. In the context of Joern, it could help you to determine the hierarchy between constructs (like classes, methods, operators and operands, etc) within your codebase.

- Program Dependence Graph (PDG)

This graph describes the relationship between our program's statements (assignments, calls, return, etc). The nature of this relationships can be either control flow like being controlled by a "if" construct or simple data dependence like a reference to a variable.

- Control Flow Graph (CFG)

This is a graph representation of the path that could be used by data when your program is running. That is the graph used internally by Joern to provide the reachableBy/reachableByFlows feature presented in the previous article.

You can find more information on the underlying data structure on their official website [here](https://cpg.joern.io).

# 0x4 Investigating with Joern - detecting the vulnerability pattern

The first step of our investigations is to find where string concatenation occurs as it's one of our criterias to determine if there's a chance that the SQL statement is corrupted. The Joern's AST allows us to detect such patterns. Indeed, the symbol "+" is an operator that is represented as a call node in the GPG, it is also part of the AST. In the AST, this node is linked to 2 child nodes: its operands. We're supposing that every "add" operation that has the type "java.lang.String" is likely to be injected into a SQL statement.

Let's consider the following piece of code:

{% highlight java %}
"somestring" + "nested_concat_string" + some_variable_ref
{% endhighlight %}

The AST of this code would look like this in pseudo-code data structure:

{% highlight bash %}
operator: {
    operation: "+",
    left_operand: "somestring" ,
    right_operand: operator {
        operation: "+",
        left_operand: "nested_concat_string" ,
        right_operand: some_variable_ref
    }
}
{% endhighlight %}

Let's try to retreive all the operands from our string additions:

{% highlight java %}
$ cpg.call("<operator>.addition").typeFullName("java.lang.String").argument.l
val res4: List[io.shiftleft.codepropertygraph.generated.nodes.Expression] = List(
  ...
  Literal(
    id = 150L,
    argumentIndex = 2,
    argumentName = None,
    code = "\" AND PASSWORD=\"",
    columnNumber = Some(value = 39),
    dynamicTypeHintFullName = ArraySeq(),
    lineNumber = Some(value = 46),
    order = 2,
    possibleTypes = ArraySeq(),
    typeFullName = "java.lang.String"
  ),
  Call(
    id = 146L,
    argumentIndex = 1,
    argumentName = None,
    code = """SELECT * FROM users" + " WHERE USERNAME=\"""",
    columnNumber = Some(value = 19),
    dispatchType = "STATIC_DISPATCH",
    dynamicTypeHintFullName = ArraySeq(),
    lineNumber = Some(value = 45),
    methodFullName = "<operator>.addition",
    name = "<operator>.addition",
    order = 1,
    possibleTypes = ArraySeq(),
    signature = "",
    typeFullName = "java.lang.String"
  ),
  ...
)
{% endhighlight %}

Not all results of this query are relevant, it is necessary to remove operands matching the following criterias:
- **Constant strings**: It is a constant string and it's value will not be influenced by the attacker. In the CPG, these nodes are associated with the type "literal".
- **Call that are addition**: we already have the underlying operands with the previous query, keeping these nodes will lead to false positives if the two operands are static. If it is not the case, you will have duplicated results because the operator and the operand are controlling the query.
- Some other cases like accessing a constant through an intermediate variable is filterable but it will be ignored as the case is not present in our code.

You can filter out the results by doing like so:

{% highlight java %}
$ cpg.call("<operator>.addition").typeFullName("java.lang.String").argument
     |    .whereNot(_.isLiteral)
     |    .whereNot(_.isCall.methodFullName("<operator>.addition"))
     |    .l
val res6: List[io.shiftleft.codepropertygraph.generated.nodes.Expression] = List(
  ...
  Identifier(
    id = 151L,
    argumentIndex = 2,
    argumentName = None,
    code = "password",
    columnNumber = Some(value = 62),
    dynamicTypeHintFullName = ArraySeq(),
    lineNumber = Some(value = 46),
    name = "password",
    order = 2,
    possibleTypes = ArraySeq(),
    typeFullName = "<unresolvedNamespace>.String"
  ),
  Identifier(
    id = 149L,
    argumentIndex = 2,
    argumentName = None,
    code = "username",
    columnNumber = Some(value = 28),
    dynamicTypeHintFullName = ArraySeq(),
    lineNumber = Some(value = 46),
    name = "username",
    order = 2,
    possibleTypes = ArraySeq(),
    typeFullName = "<unresolvedNamespace>.String"
  )
)
{% endhighlight %}

Now, all the parameters listed may impact the content of the SQL statement but we still have to prove (or at least get hints) that they control the SQL statement. Fortunately, the other graphs within the CPG allows us to find a path between the variables/calls we just found into queryForMap first parameter.

{% highlight bash  %}
$ def source = cpg.call("<operator>.addition")
     |    .typeFullName("java.lang.String").argument
     |    .whereNot(_.isLiteral)
     |    .whereNot(_.isCall.methodFullName("<operator>.addition")) 
$ def sink = cpg.call
     |    .methodFullName("org.springframework.jdbc.core.JdbcTemplate.queryForMap:.*")
     |    .argument.argumentIndex(1)
$ sink.reachableByFlows(source).p
val res3: List[String] = List(
  """
┌─────────────────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────┬────┬────────────┬──────────────────┐
│nodeType         │tracked                                                                                                        │line│method      │file              │
├─────────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────┼────┼────────────┼──────────────────┤
│Identifier       │"Login with: " + username                                                                                      │30  │login       │WebController.java│
│Identifier       │loginSuccess(username, password)                                                                               │32  │login       │WebController.java│
│MethodParameterIn│loginSuccess(this, String username, String password)                                                           │41  │loginSuccess│WebController.java│
│Identifier       │username == null                                                                                               │42  │loginSuccess│WebController.java│
│Identifier       │"SELECT * FROM users" + " WHERE USERNAME=\"" + username                                                        │46  │loginSuccess│WebController.java│
│Call             │"SELECT * FROM users" + " WHERE USERNAME=\"" + username + "\" AND PASSWORD=\"" + password + "\""               │45  │loginSuccess│WebController.java│
│Identifier       │String query = "SELECT * FROM users" + " WHERE USERNAME=\"" + username + "\" AND PASSWORD=\"" + password + "\""│45  │loginSuccess│WebController.java│
│Identifier       │com.example.vulnspring.WebController.logger.debug(query)                                                       │48  │loginSuccess│WebController.java│
│Identifier       │this.jdbcTemplate.queryForMap(query)                                                                           │50  │loginSuccess│WebController.java│
└─────────────────┴───────────────────────────────────────────────────────────────────────────────────────────────────────────────┴────┴────────────┴──────────────────┘""",
  """
┌──────────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────┬────┬────────────┬──────────────────┐
│nodeType  │tracked                                                                                                        │line│method      │file              │
├──────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────┼────┼────────────┼──────────────────┤
│Identifier│"SELECT * FROM users" + " WHERE USERNAME=\"" + username                                                        │46  │loginSuccess│WebController.java│
│Call      │"SELECT * FROM users" + " WHERE USERNAME=\"" + username + "\" AND PASSWORD=\"" + password + "\""               │45  │loginSuccess│WebController.java│
│Identifier│String query = "SELECT * FROM users" + " WHERE USERNAME=\"" + username + "\" AND PASSWORD=\"" + password + "\""│45  │loginSuccess│WebController.java│
│Identifier│com.example.vulnspring.WebController.logger.debug(query)                                                       │48  │loginSuccess│WebController.java│
│Identifier│this.jdbcTemplate.queryForMap(query)                                                                           │50  │loginSuccess│WebController.java│
└──────────┴───────────────────────────────────────────────────────────────────────────────────────────────────────────────┴────┴────────────┴──────────────────┘""",
  """
┌─────────────────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────┬────┬────────────┬──────────────────┐
│nodeType         │tracked                                                                                                        │line│method      │file              │
├─────────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────┼────┼────────────┼──────────────────┤
│Identifier       │"Login with: " + username + ":" + password                                                                     │30  │login       │WebController.java│
│Identifier       │loginSuccess(username, password)                                                                               │32  │login       │WebController.java│
│MethodParameterIn│loginSuccess(this, String username, String password)                                                           │41  │loginSuccess│WebController.java│
│Identifier       │password == null                                                                                               │42  │loginSuccess│WebController.java│
│Identifier       │"SELECT * FROM users" + " WHERE USERNAME=\"" + username + "\" AND PASSWORD=\"" + password                      │46  │loginSuccess│WebController.java│
│Call             │"SELECT * FROM users" + " WHERE USERNAME=\"" + username + "\" AND PASSWORD=\"" + password + "\""               │45  │loginSuccess│WebController.java│
│Identifier       │String query = "SELECT * FROM users" + " WHERE USERNAME=\"" + username + "\" AND PASSWORD=\"" + password + "\""│45  │loginSuccess│WebController.java│
│Identifier       │com.example.vulnspring.WebController.logger.debug(query)                                                       │48  │loginSuccess│WebController.java│
│Identifier       │this.jdbcTemplate.queryForMap(query)                                                                           │50  │loginSuccess│WebController.java│
└─────────────────┴───────────────────────────────────────────────────────────────────────────────────────────────────────────────┴────┴────────────┴──────────────────┘""",
  """
┌──────────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────┬────┬────────────┬──────────────────┐
│nodeType  │tracked                                                                                                        │line│method      │file              │
├──────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────┼────┼────────────┼──────────────────┤
│Identifier│"SELECT * FROM users" + " WHERE USERNAME=\"" + username + "\" AND PASSWORD=\"" + password                      │46  │loginSuccess│WebController.java│
│Call      │"SELECT * FROM users" + " WHERE USERNAME=\"" + username + "\" AND PASSWORD=\"" + password + "\""               │45  │loginSuccess│WebController.java│
│Identifier│String query = "SELECT * FROM users" + " WHERE USERNAME=\"" + username + "\" AND PASSWORD=\"" + password + "\""│45  │loginSuccess│WebController.java│
│Identifier│com.example.vulnspring.WebController.logger.debug(query)                                                       │48  │loginSuccess│WebController.java│
│Identifier│this.jdbcTemplate.queryForMap(query)                                                                           │50  │loginSuccess│WebController.java│
└──────────┴───────────────────────────────────────────────────────────────────────────────────────────────────────────────┴────┴────────────┴──────────────────┘"""
)

{% endhighlight %}

We're done with the vulnerability signature, we found a few results but they didn't prove that the code is exploitable. It only means that a concatenation appened somewhere with a variable who's value is not known at compile time. And the dynamic variable is used later in that code to create a SQL statement that might be corrupted. This is the same thing we did in the previous blog post: testing the reachablility between CPG nodes. Joern tracks the data through calls, variable references, method return values and so on to produce such results. This is the path in the code that is returned by reachableBy* functions.

The main drawback of this assumtion is that Joern found two results that are not directly related the SQLi itself. Indeed, the first and the third result exist because a logging string has been created with a concatenation of a variable that might carry an injection payload. This is some kind of false positive even if there is an actual vulnerability. One way to fix this would be to tell Joern exlicitely what kind of edge it should use in the CPG to reach the call responsible of executing the SQL statement but I don't think this feature exists yet in Joern, I haven't explored deeper as manual traversal is tideous. For now, this is the best approach I could get in order to get the lowest rate of false positive while detecting almost all injections I knew were present in the codebase.

# 0x4 Investigating with Joern - debugging for real-life scenarios

As you could see, our assumtions are good enough for automated scanning but sometimes you will have false positives, as every tool. We will need to investigate with other (dirty) techniques in order to gather as much information as possible. The first questions I would ask myself are: Where that string comes from? Is it provided by the user directly? Or it is a value that was retreived from a database?

The first thing to do in that case is to find out in which method the vulnerable code is located, just by going up in the AST (this is done by the "repeat" thing in the query). The query uses the "dump" functionnality which shows the full source code of the selected methods. This is a very cool feature for debugging.

{% highlight java %}
$ sink.reachableByFlows(source).map(e => e.elements.last)
        .dedup
        .repeat(_.astParent)(_.until(_.isMethod))
        .isMethod
        .dump.l

val res10: List[String] = List(
  """	private String loginSuccess(String username, String password) { /* <=== com.example.vulnspring.WebController.loginSuccess:<unresolvedSignature>(2) */ 
		if (username == null || password == null)
			return null;
		try {
			String query = "SELECT * FROM users" +
				" WHERE USERNAME=\"" + username + "\" AND PASSWORD=\"" + password + "\"";
			
			logger.debug(query);
			
			Map<String, Object> result = jdbcTemplate.queryForMap(query);
			return result.get("username").toString();

		} catch (EmptyResultDataAccessException e) {
			return null;
		}
	}
"""
)
{% endhighlight %}

Now that we are able to find the vulnerable method, Joern is able to provide us the list of callers of this method, and recursively! Awesome, isn't it? This can be done again with the repeat steps in the query. This time we'll use the "emit" instruction in the repeat step, it keeps track of the methods we found while traversing the call graph.

{% highlight java %}
vulnerable_method.repeat(_.caller)(_.emit(_.isMethod).until(_.isMethod)).dump.l
val res15: List[String] = List(
  """	private String loginSuccess(String username, String password) { /* <=== com.example.vulnspring.WebController.loginSuccess:<unresolvedSignature>(2) */ 
		if (username == null || password == null)
			return null;
		try {
			String query = "SELECT * FROM users" +
				" WHERE USERNAME=\"" + username + "\" AND PASSWORD=\"" + password + "\"";
			
			logger.debug(query);
			
			Map<String, Object> result = jdbcTemplate.queryForMap(query);
			return result.get("username").toString();

		} catch (EmptyResultDataAccessException e) {
			return null;
		}
	}
""",
  """	@PostMapping("/login") /* <=== com.example.vulnspring.WebController.login:<unresolvedSignature>(3) */ 
	public HttpEntity<String> login(
			HttpSession session,
			@RequestParam(name = "username", required = true) String username,
			@RequestParam(name = "password", required = true) String password
		) {
		
		logger.debug("Login with: " + username + ":" + password);
		
		String logged_user = loginSuccess(username, password);
		if (logged_user != null) {
			session.setAttribute("username", username);
			return new HttpEntity<>("logged in \\o/, welcome " + logged_user + " !\n");
		}
		logger.debug("Failed login for " + username);
		return new HttpEntity<>("failed :c\n");
	}
"""
)
{% endhighlight %}

As we can see, we end up on the "login" method in which the payload is provided by the user. Now we have the proof we needed to tell that this code is vulnerable. It doesn't looks that impressive here but I had cases where I had a call chain of 10 or more methods and Joern saved me a lot of time for vulnerability investigations.

# 0x5 Ending note

Although this framework is very powerfull and will save you a lot of time with a bit of practice, this approach alone will suffer from severe limitations. Indeed, there are a lot of configuration dependant issues and dependency code that is not available and that is likely to be subject to vulnerabilities. For example, you will have to look manually at the app's config or try dynamic testing to determine if some Spring actuators endpoints are activated (and even here you have to be carefull as the route mapping might be changed, dynamic testing alone is not sufficient).

Also, attacks exploiting logic bugs may not be relevant to test whit static analysis as it requires a deep knowledge of the application. If you try to replicate patterns for this kind of bugs, you may end up with signatures that are either too complex or too specific. The code analysis rules will be build from "noise" in some way.

With my current experience, the automated detection rules are only capable of detecting different command/statement injection patterns (which is already very insteresting). It is also possible to spot some IDORs and Broken Access Control issues but this is very dependant of the app's implementation, thus leading to a high rate of false positives and false negatives for now.

Thanks for reading.
