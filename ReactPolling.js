 //https://overreacted.io/making-setinterval-declarative-with-react-hooks/

import React, { useState, useEffect, useRef } from 'react';

export const useInterval = (callback, delay) => {

  const savedCallback = useRef();

  useEffect(() => {
    savedCallback.current = callback;
  }, [callback]);


  useEffect(() => {
    function tick() {
      savedCallback.current();
    }
    if (delay !== null) {
      const id = setInterval(tick, delay);
      return () => clearInterval(id);
    }
  }, [delay]);
}


import useInterval from '../utils';

const MyPage = () => {

  useInterval(() => {
    // put your interval code here.
  }, 1000 * 10);

  return <div>my page content</div>;
}
