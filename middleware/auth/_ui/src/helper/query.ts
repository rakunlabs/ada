const getRedirectPath = () => {
  const searchParams = (new URLSearchParams(window.location.search));
  // check redirect_path
  const redirectPath = searchParams.get('redirect_path');

  if (!!redirectPath) {
    return redirectPath;
  }

  return "/";
}

const getRedirectUri = () => {
  const searchParams = (new URLSearchParams(window.location.search));

  const redirectURI = searchParams.get('redirect_uri');
  if (!!redirectURI) {
    return redirectURI;
  }

  return "";
}

const isResponseTypeCode = () => {
  const searchParams = (new URLSearchParams(window.location.search));
  // check response_code
  const responseCode = searchParams.get('response_type');
  if (!!responseCode) {
    if (responseCode === 'code') {
      return true;
    }
  }

  return false;
}

export { getRedirectPath, getRedirectUri, isResponseTypeCode };
