<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">

    <title>Laravel</title>
</head>
<body>
<form action="{{ route("do-login") }}" method="POST">
    @csrf
    <div>
        <label for="username">username</label>
        <input name="username" id="username" type="text"/>
    </div>
    <div>
        <label for="password">password</label>
        <input name="password" id="password" type="password"/>
    </div>
    <div>
        <button>submit</button>
    </div>
</form>
</body>
</html>
