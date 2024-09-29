@php /** @var \Aws\Result $authRes */  @endphp

<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">

    <title>Laravel</title>
</head>
<body>
<h2>Login Successfully.</h2>
<dl>
    <dt>access token</dt>
    <dd>{{ $authRes['AuthenticationResult']['AccessToken'] }}</dd>
</dl>

</body>
</html>
