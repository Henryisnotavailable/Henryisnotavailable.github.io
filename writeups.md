---
layout: default
title: All writeups
permalink: /writeups/
---

{% assign writeups = site.categories.writeups | sort: "date" | reverse %}
{% if writeups.size > 0 %}
<ul>
  {% for post in writeups %}
    <li><a href="{{ post.url | relative_url }}">{{ post.date | date: "%B %Y" }} - {{ post.title }}</a></li>
  {% endfor %}
</ul>
{% else %}
<p>No writeups have been published yet.</p>
{% endif %}
