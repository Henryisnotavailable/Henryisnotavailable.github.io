---
layout: default
title: All writeups
permalink: /writeups/
---

{% assign writeups = site.writeups | sort: "date" | reverse %}
{% if writeups.size > 0 %}
<ul>
  {% for post in writeups %}
    <li><a href="{{ post.url | relative_url }}">{{ post.title }}</a> {{post.excerpt}}</li>
  {% endfor %}
</ul>
{% else %}
<p>No writeups have been published yet.</p>
{% endif %}
