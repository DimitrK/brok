import React from 'react';
import {ApiClientError} from '../api/errors';

type ErrorNoticeProps = {
  error: unknown;
};

const describeError = (error: unknown) => {
  if (error instanceof ApiClientError) {
    const correlationText = error.correlationId ? ` (correlation: ${error.correlationId})` : '';
    return `${error.reason}: ${error.message}${correlationText}`;
  }

  if (error instanceof Error) {
    return error.message;
  }

  return 'Unknown error';
};

export const ErrorNotice = ({error}: ErrorNoticeProps) => {
  if (!error) {
    return null;
  }

  return <p className="error-notice">{describeError(error)}</p>;
};
