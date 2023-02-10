# Why I archive the repo

I had started the repository when I discovered a [hole in KeePass](https://clattenzaun.de/blog/passwoerter-auf-dem-silbertablett/) and discussed it with a reporter from Heise in cc with reichl. I do not share his views in many respects.

I originally wanted to provide a PR with this repo for him to improve the things that bother me, even though he categorically refused to accept such "strong" changes.

In the end, I was too lazy to implement all my ideas anyway, so in the end I just used the repo to check what changed in each version.

I'll stop doing that now, after the last security vulnerability and his take on it as he discusses it, I've finally switched to [KeePassXC](https://github.com/keepassxreboot/keepassxc) and will no longer use KeePass itself.

KeePass XC is not only more modern in many ways, but the project also puts a lot of effort into security from my point of view. The availability on GitHub and the fact that there are several developers working on the project there have only made this development easier for me.

I can therefore only recommend that everyone switch to [KeePassXC](https://github.com/keepassxreboot/keepassxc) and leave KeePass behind.


# KeePass - Fork

Welcome to this git reposetory. Here you find my fork to KeePass. On the one hand I add some small features which are interesting for me and on the other hand I try to fix some lecks.

Over time the fork could deviate more and more from the original.

## motives

One of the reasons why I started with the fork is to be found on CLattenzaun.de another one is based in the plugin HttpPlugin and because I find KeePass great. I also find it more convenient for people to work on KeePass via GitHub than sending emails to Dominik Reichl via SourceForge.

Also, it has to be said that on Github the code is more visible than on SourceForge. At least that's my opinion.

## Brief explanation on branching:

In general I use Git Flow therefore

* productive = my published version of the fork, at the moment a fork of the origin code. see reichl branch
* reichl = the unchanged code officially published by Dominik Reichl
* stable = my current development branch
