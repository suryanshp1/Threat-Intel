import { useEffect, useRef, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { ArrowLeft, ArrowRight, Compass, X } from "lucide-react";
import { tourSteps } from "./tour-data";
import "./tour.css";

export function TourWelcome({ onStart, onDismiss }: { onStart: () => void; onDismiss: () => void }) {
  return <section className="tour-welcome" aria-label="Welcome to Sentinel">
    <Compass size={24} aria-hidden="true" />
    <div><h2>Find your way around Sentinel</h2><p>Take a short tour of eight screens, from CVE research to source evidence.</p></div>
    <button className="button primary" onClick={onStart}>Start tour <ArrowRight size={15} /></button>
    <button className="icon-button" aria-label="Dismiss tour invitation" onClick={onDismiss}><X size={18} /></button>
  </section>;
}

export function UserTour({ onClose }: { onClose: () => void }) {
  const [index, setIndex] = useState(0);
  const step = tourSteps[index];
  const dialog = useRef<HTMLDialogElement>(null);
  const title = useRef<HTMLHeadingElement>(null);
  const location = useLocation();
  const origin = useRef(location.pathname + location.search + location.hash);
  const navigate = useNavigate();
  const last = index === tourSteps.length - 1;
  const finish = () => {
    dialog.current?.close();
    navigate(origin.current, { replace: true });
    onClose();
  };
  useEffect(() => {
    const element = dialog.current;
    const overflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    element?.showModal();
    return () => {
      element?.close();
      document.body.style.overflow = overflow;
    };
  }, []);
  useEffect(() => {
    navigate(step.path, { replace: true });
    title.current?.focus();
  }, [step.path, navigate]);
  return <dialog ref={dialog} className="user-tour" aria-labelledby="tour-title" aria-describedby="tour-description"
    onCancel={event => { event.preventDefault(); finish(); }}
    onKeyDown={event => {
      if (event.key !== "Tab") return;
      const controls = Array.from(dialog.current?.querySelectorAll<HTMLButtonElement>("button:not(:disabled)") || []);
      const first = controls[0], last = controls[controls.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault(); last?.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault(); first?.focus();
      }
    }}>
    <div className="tour-topline"><span><Compass size={16} aria-hidden="true" /> SENTINEL / USER TOUR</span><button className="icon-button" aria-label="Close user tour" onClick={finish}><X size={18} /></button></div>
    <div className="tour-progress" aria-label={`Step ${index + 1} of ${tourSteps.length}`}>
      {tourSteps.map((item, position) => <span key={item.path} className={position <= index ? "reached" : ""} />)}
    </div>
    <div className="tour-copy" key={step.path}>
      <p className="tour-eyebrow">{String(index + 1).padStart(2, "0")} / {step.label}</p>
      <h2 id="tour-title" ref={title} tabIndex={-1}>{step.title}</h2>
      <p id="tour-description">{step.description}</p>
      <p className="tour-tip">{step.tip}</p>
    </div>
    <div className="tour-controls">
      <button className="tour-skip" onClick={finish}>Exit tour</button>
      <span className="tour-count">{index + 1} / {tourSteps.length}</span>
      <button className="button" disabled={index === 0} onClick={() => setIndex(index - 1)}><ArrowLeft size={14} /> Back</button>
      <button className="button primary" onClick={() => last ? finish() : setIndex(index + 1)}>{last ? "Finish tour" : "Next"}{!last && <ArrowRight size={14} />}</button>
    </div>
    <p className="tour-return">Closing returns you to your starting screen. Press Esc to exit.</p>
  </dialog>;
}
