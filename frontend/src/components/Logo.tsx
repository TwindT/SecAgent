interface LogoProps {
  size?: number;
}

function Logo({ size = 32 }: LogoProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 48 48"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
    >
      <defs>
        <linearGradient
          id="secagent-grad"
          x1="0"
          y1="0"
          x2="48"
          y2="48"
          gradientUnits="userSpaceOnUse"
        >
          <stop offset="0%" stopColor="#5BA3FF" />
          <stop offset="100%" stopColor="#5EEAD4" />
        </linearGradient>
      </defs>

      {/* Rounded square background */}
      <rect width="48" height="48" rx="12" fill="url(#secagent-grad)" />

      {/* Shield outline - soft rounded */}
      <path
        d="M24 12L15 16.5V24C15 29.5 18.6 34.5 24 36C29.4 34.5 33 29.5 33 24V16.5L24 12Z"
        stroke="white"
        strokeWidth="2.2"
        strokeLinejoin="round"
        fill="none"
      />

      {/* Scan line */}
      <line
        x1="18"
        y1="23"
        x2="30"
        y2="23"
        stroke="white"
        strokeWidth="2"
        strokeLinecap="round"
        opacity="0.75"
      />

      {/* Focus point */}
      <circle cx="24" cy="23" r="2.5" fill="white" />
    </svg>
  );
}

export default Logo;
