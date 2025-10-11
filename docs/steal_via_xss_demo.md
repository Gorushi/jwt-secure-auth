# XSS를 통한 토큰 탈취 시연 절차 (개념 증명)

> **경고**: 이 문서는 교육 목적으로 작성되었으며, 설명된 모든 절차는 **반드시 통제된 로컬 개발 환경에서만** 수행해야 합니다. 실제 서비스에 절대로 시도해서는 안 됩니다.

## 1. XSS란?

XSS (Cross-Site Scripting)는 공격자가 웹 애플리케이션에 악성 스크립트를 삽입하여, 다른 사용자의 브라우저에서 해당 스크립트가 실행되게 하는 공격입니다. 만약 웹사이트가 사용자의 입력을 제대로 검증(Sanitization)하지 않고 그대로 페이지에 표시한다면 XSS 공격에 매우 취약해집니다.

## 2. `LocalStorage`와 토큰 탈취 시나리오

1.  **피해자**는 정상적으로 서비스에 로그인하고, 브라우저의 `LocalStorage`에 Access Token을 저장합니다. (`LocalStorage`는 JavaScript로 자유롭게 접근이 가능합니다.)
2.  **공격자**는 XSS 취약점이 있는 게시판이나 검색창에 악성 스크립트가 포함된 게시물/댓글을 작성합니다.
    -   이 스크립트의 역할: "현재 페이지의 `LocalStorage`에서 `access_token` 항목을 읽어서, 공격자의 서버로 전송하라."
3.  **피해자**가 공격자의 악성 스크립트가 포함된 페이지를 열람합니다.
4.  피해자의 브라우저는 페이지를 렌더링하다가 공격자가 심어놓은 스크립트를 아무 의심 없이 실행합니다.
5.  스크립트는 피해자의 토큰을 성공적으로 탈취하여 공격자에게 몰래 전송합니다.
6.  공격자는 탈취한 토큰을 사용하여 `token_replay.py`에서처럼 피해자 행세를 하며 보호된 API에 접근합니다.

## 3. 로컬 환경에서 간단 시연

### `vulnerable_page.html` 작성
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>XSS Vulnerable Page</title>
</head>
<body>
    <h1>검색 결과</h1>
    <p>
        "<strong></strong>"에 대한 검색 결과가 없습니다.
    </p>

    <script>
        // URL에서 'query' 파라미터를 가져와서 페이지에 그대로 출력 (XSS 취약점의 원인!)
        const urlParams = new URLSearchParams(window.location.search);
        const query = urlParams.get('query');
        
        // innerHTML을 사용해 HTML 파싱을 허용하면 스크립트가 실행될 수 있습니다.
        if (query) {
            document.querySelector('strong').innerHTML = query; 
        }
    </script>
</body>
</html>
